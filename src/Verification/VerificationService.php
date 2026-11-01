<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\Carbon;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Codes\CodeCheck;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Issues challenges for the current identity's factors and verifies the codes
 * submitted against them.
 *
 * A factor whose driver delivers codes (email, SMS) has its codes sent and
 * checked through `Codes\CodeService`, bound to the factor, the identity, the
 * application, the session and the purpose: the application a bound
 * `ApplicationResolver` names for the request, otherwise the default guard's
 * name, and the Laravel session the request runs in. Every other factor goes
 * through its driver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerificationService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Drivers\DriverResolver  $drivers
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorStateCache  $cache
     */
    public function __construct(

        /** The container the store, dispatcher and config are read from. */
        private Container $container,

        /** The resolver of the factor drivers. */
        private DriverResolver $drivers,

        /** The per-request cache of the identity's factor state. */
        private FactorStateCache $cache,
    ) {}

    /**
     * Issue a challenge for the given factor through the named driver, for the
     * purpose given.
     *
     * For a driver that delivers codes, a code bound to this session and the
     * purpose is sent through the code service, and the outcome returned:
     * sent, or refused with its reason. For any other driver, its
     * `issueChallenge()` runs and nothing is returned. `MfaChallengeIssued` is
     * dispatched unless the send was refused.
     *
     * Throws `FactorOwnershipMismatchException` when the supplied factor does
     * not belong to the current identity, closing the cross-account
     * factor-tampering primitive. Throws `FactorDriverMismatchException` when
     * the requested driver name does not match the factor's own `getType()`:
     * routing one driver's logic through a factor registered against another is
     * always a caller bug.
     *
     * The driver is resolved from the given registry: the manager the challenge
     * was issued through.
     *
     * @param  \Illuminate\Support\Manager  $registry
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return ?\SineMacula\Laravel\Mfa\Codes\SendResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     * @throws \Throwable
     */
    public function challenge(Manager $registry, string $driver, Factor $factor, Purpose $purpose = Purpose::SIGN_IN): ?SendResult
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return null;
        }

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        $resolved = $this->drivers->resolve($registry, $driver);
        $result   = null;

        // A delivered code is sent bound to this session and purpose, and
        // neither resets a failure count nor lifts a lockout. TOTP and backup
        // codes have no per-challenge secret to mint, so their
        // `issueChallenge()` is a no-op.
        if ($resolved instanceof CodeDeliveryDriver) {
            $result = $this->container->make(CodeService::class)->send($identity, $factor, $this->binding($identity, $purpose), $resolved);
        } else {
            $resolved->issueChallenge($factor);
        }

        if ($result === null || $result->wasSent()) {
            $events = $this->container->make(Dispatcher::class);
            $events->dispatch(new MfaChallengeIssued($identity, $factor, $driver));
        }

        return $result;
    }

    /**
     * Verify a submitted code against the given factor through the named
     * driver, for the purpose given.
     *
     * - Rejects the attempt when the factor is locked.
     * - Checks the code: through the code service, against the code sent for
     *   this session and the purpose, for a driver that delivers codes;
     *   through the driver's verification logic otherwise.
     * - On success: resets attempts, stamps the factor's verified-at, records
     *   the identity-level verification through the bound store, dispatches
     *   `MfaVerified`.
     * - On failure: increments attempts, applies a lockout once the configured
     *   per-driver threshold is reached, dispatches `MfaVerificationFailed`
     *   with a machine-readable reason.
     *
     * Throws `FactorOwnershipMismatchException` when the supplied factor does
     * not belong to the current identity, closing the cross-account MFA-bypass
     * primitive. Throws `FactorDriverMismatchException` when the requested
     * driver name does not match the factor's own `getType()`.
     *
     * The driver is resolved from the given registry: the manager the
     * verification was called on.
     *
     * @param  \Illuminate\Support\Manager  $registry
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function verify(Manager $registry, string $driver, Factor $factor, #[\SensitiveParameter] string $code, Purpose $purpose = Purpose::SIGN_IN): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return false;
        }

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        $events = $this->container->make(Dispatcher::class);

        if ($factor->isLocked()) {
            $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, FailureReason::LOCKED, 'The factor is locked after too many failed attempts.'));

            return false;
        }

        $resolved = $this->drivers->resolve($registry, $driver);
        $check    = null;

        if ($resolved instanceof CodeDeliveryDriver) {
            $check = $this->container->make(CodeService::class)->check($factor, $this->binding($identity, $purpose), $code);
            $valid = $check === CodeCheck::ACCEPTED;
        } else {
            $valid = $resolved->verify($factor, $code);
        }

        if ($factor instanceof EloquentFactor) {
            $this->applyVerificationOutcome($factor, $valid);
        }

        $this->finalizeVerification($identity, $factor, $driver, $valid, $check, $events);

        return $valid;
    }

    /**
     * Persist the post-driver verification outcome on the factor row.
     *
     * Successful verification stamps `verified_at` and resets attempts;
     * failure increments the attempt counter and, once it
     * reaches `mfa.attempts.factor_limit`, locks the factor for
     * `mfa.attempts.lockout_seconds`. Non-Eloquent factors carry no row to
     * mutate and skip both branches before this method is even called.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  bool  $valid
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function applyVerificationOutcome(EloquentFactor $factor, bool $valid): void
    {
        if ($valid) {
            $factor->recordVerification();
            $factor->persist();

            return;
        }

        $factor->recordAttempt();

        $attempts = new AttemptSettings($this->container->make('config'));

        if ($factor->getAttempts() >= $attempts->factorLimit()) {
            $factor->applyLockout(Carbon::now()->addSeconds($attempts->lockoutSeconds()));
        }

        $factor->persist();
    }

    /**
     * Apply the post-verify side effects: stamp the identity-level verification
     * through the bound store and dispatch `MfaVerified` on success, or
     * classify the failure and dispatch `MfaVerificationFailed` with a
     * machine-readable reason on failure.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  bool  $valid
     * @param  ?\SineMacula\Laravel\Mfa\Codes\CodeCheck  $check
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function finalizeVerification(MultiFactorAuthenticatable $identity, Factor $factor, string $driver, bool $valid, ?CodeCheck $check, Dispatcher $events): void
    {
        if ($valid) {
            /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
            $store = $this->container->make(MfaVerificationStore::class);
            $store->markVerified($identity);
            $this->cache->clear($identity);

            $events->dispatch(new MfaVerified($identity, $factor, $driver));

            return;
        }

        // Classify the failure: a delivered code by what its check found; any
        // other factor as not confirmed when it holds no secret, so its
        // enrolment never completed, and as an invalid code otherwise.
        [$reason, $detail] = match (true) {
            $check !== null               => [$check->failure() ?? FailureReason::INVALID_CODE, $check->detail()],
            $factor->getSecret() === null => [FailureReason::NOT_CONFIRMED, 'The factor has no secret, so its enrolment never completed.'],
            default                       => [FailureReason::INVALID_CODE, 'The code did not match.'],
        };

        $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, $reason, $detail));
    }

    /**
     * What a delivered code for the identity is bound to in this request: the
     * identity, the application, the Laravel session and the purpose.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function binding(MultiFactorAuthenticatable $identity, Purpose $purpose): ProofBinding
    {
        $key = $identity->getAuthIdentifier();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw new UnsupportedIdentifierException(sprintf('A delivered code is bound to an identity with a string or integer key; got [%s].', get_debug_type($key)));
        }

        return new ProofBinding(
            CurrentIdentity::typeOf($identity),
            (string) $key,
            $this->application(),
            $this->container->make(Session::class)->getId(),
            $purpose,
        );
    }

    /**
     * The application the request is for: the one a bound
     * `ApplicationResolver` names, otherwise the default guard's name.
     *
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function application(): string
    {
        if ($this->container->bound(ApplicationResolver::class) && $this->container->bound('request')) {
            return $this->container->make(ApplicationResolver::class)->resolve($this->container->make('request'));
        }

        $guard = $this->container->make(Repository::class)->get('auth.defaults.guard');

        return is_string($guard) && $guard !== '' ? $guard : 'default';
    }
}
