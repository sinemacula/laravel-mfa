<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
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
 * through its driver. Every verification is an attempt made through
 * `Attempts\AttemptService`, so it is counted, and refused while a lockout
 * applies, whichever way its code is checked.
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
     * purpose is sent through the code service, and the outcome returned: sent,
     * or refused with its reason. For any other driver, its `issueChallenge()`
     * runs and nothing is returned. `MfaChallengeIssued` is dispatched unless
     * the send was refused.
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

        // A delivered code is sent bound to this session and purpose. Sending a
        // code resets no count and lifts no lockout: only a success of the
        // factor resets its failures in a row, so a resend cannot be used to
        // wipe a lockout. TOTP and backup codes have no per-challenge secret to
        // mint, so their `issueChallenge()` is a no-op.
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
     * - The attempt is made through the attempt service, charged to the current
     *   identity, the factor and the request's IP address, for the purpose:
     *   refused without checking the code while a lockout applies, otherwise
     *   counted with its outcome under the identity's factor state lock.
     * - The code is checked against the factor as stored under that lock, not
     *   the instance passed in, so a secret replaced in the meantime is the one
     *   checked, and a factor removed in the meantime is reported as not found
     *   without checking anything: through the code service, against the code
     *   sent for this session and the purpose, for a driver that delivers
     *   codes; through the driver's verification logic otherwise.
     * - On success, inside the same transaction: a delivered code is used up
     *   and the factor's verified-at stamped, so they commit with the count and
     *   two requests with the same code cannot both pass.
     * - Once the code is checked, the instance passed in is brought up to date
     *   with the stored factor. On success the identity-level verification is
     *   recorded through the bound store and `MfaVerified` dispatched; on
     *   failure `MfaVerificationFailed` is dispatched with a machine-readable
     *   reason, `locked` for an attempt a lockout refused and `not_found` for a
     *   factor removed in the meantime.
     *
     * Throws `FactorOwnershipMismatchException` when the supplied factor does
     * not belong to the current identity, closing the cross-account MFA-bypass
     * primitive, before anything is counted. Throws
     * `FactorDriverMismatchException` when the requested driver name does not
     * match the factor's own `getType()`.
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
     * @throws \Throwable
     */
    public function verify(Manager $registry, string $driver, Factor $factor, #[\SensitiveParameter] string $code, Purpose $purpose = Purpose::SIGN_IN): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return false;
        }

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        $events   = $this->container->make(Dispatcher::class);
        $resolved = $this->drivers->resolve($registry, $driver);
        $binding  = $resolved instanceof CodeDeliveryDriver ? $this->binding($identity, $purpose) : null;
        $verified = $factor;
        $check    = null;

        // The current identity's own session makes the attempt, so the identity
        // is charged for it.
        $outcome = $this->container->make(AttemptService::class)->attempt(
            new Attempt($identity, $factor, $purpose, $this->ip()),
            function (?Factor $stored) use ($resolved, $binding, $code, &$verified, &$check): bool {

                $verified = $stored ?? $verified;

                return $this->isAccepted($resolved, $binding, $verified, $code, $check);
            },
        );

        if ($outcome->lockout !== null || $outcome->isNotFound()) {

            [$reason, $detail] = $outcome->lockout !== null
                ? [FailureReason::LOCKED, $outcome->lockout->detail()]
                : [FailureReason::NOT_FOUND, 'The factor is no longer among the identity\'s factors.'];

            $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, $reason, $detail));

            return false;
        }

        if ($factor instanceof Model && $verified instanceof Model && $verified !== $factor) {
            $factor->setRawAttributes($verified->getAttributes(), true);
        }

        $this->finalizeVerification($identity, $factor, $driver, $outcome->passed, $check, $events);

        return $outcome->passed;
    }

    /**
     * Check the code against the factor as stored, and record a success on it:
     * through the code service, under the binding, for a driver that delivers
     * codes, recording what the check found in `$check`; through the driver
     * otherwise.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $driver
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  ?\SineMacula\Laravel\Mfa\Enums\CodeCheck  $check
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     */
    private function isAccepted(FactorDriver $driver, ?ProofBinding $binding, Factor $factor, #[\SensitiveParameter] string $code, ?CodeCheck &$check): bool
    {
        if ($binding !== null) {
            $check = $this->container->make(CodeService::class)->check($factor, $binding, $code);
        }

        $accepted = $check === null ? $driver->verify($factor, $code) : $check === CodeCheck::ACCEPTED;

        if ($accepted && $factor instanceof EloquentFactor) {
            $factor->recordVerification();
            $factor->persist();
        }

        return $accepted;
    }

    /**
     * The IP address of the request being served, as resolved through the
     * application's trusted proxies, or `null` outside a request.
     *
     * @return ?string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function ip(): ?string
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;

        return $request instanceof Request ? $request->ip() : null;
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
     * @param  ?\SineMacula\Laravel\Mfa\Enums\CodeCheck  $check
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
        return new ProofBinding(
            CurrentIdentity::typeOf($identity),
            self::identityKey($identity),
            $this->application(),
            $this->container->make(Session::class)->getId(),
            $purpose,
        );
    }

    /**
     * The identity's key as a string, which a delivered code is bound to.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function identityKey(MultiFactorAuthenticatable $identity): string
    {
        $key = $identity->getAuthIdentifier();

        if ((!is_string($key) && !is_int($key)) || $key === '') {
            throw new UnsupportedIdentifierException(sprintf('A delivered code is bound to an identity with a string or integer key; got [%s].', get_debug_type($key)));
        }

        return (string) $key;
    }

    /**
     * The application the request is for: the one a bound `ApplicationResolver`
     * names, otherwise the default guard's name.
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

        return $this->container->make(AuthManager::class)->getDefaultDriver();
    }
}
