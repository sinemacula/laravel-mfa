<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\RequestIp;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Contracts\CodeDeliveryDriver;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Factors\FactorChannel;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Issues challenges for the factors of the identity the request serves and
 * verifies the codes submitted against them: a pending session's identity when
 * its credential allows sending a code (`mfa.send_code`) or verifying
 * (`mfa.verify`), otherwise the signed-in person (see
 * `Context\CallerContextResolver`); with neither, nothing is sent or checked.
 *
 * A factor whose driver delivers codes (email, SMS) has its codes sent and
 * checked through `Codes\CodeService`, bound to the factor, the identity, the
 * application, the session and the purpose: on a pending session its own
 * application and public id; otherwise the application a bound
 * `ApplicationResolver` names for the request, or the default guard's name,
 * and the Laravel session the request runs in. Every other factor goes
 * through its driver. Every verification is an attempt made through
 * `Attempts\AttemptService`, so it is counted, and refused while a lockout
 * applies, whichever way its code is checked. A verification that passes
 * records its proof on the identity's current sign-in through
 * `Proofs\ProofService`.
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
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofService  $proofs
     */
    public function __construct(

        /** The container the services, dispatcher and session are read from. */
        private Container $container,

        /** The resolver of the factor drivers. */
        private DriverResolver $drivers,

        /** The recorder of the proofs a verification makes. */
        private ProofService $proofs,
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
        $caller = $this->callers()->resolve(PendingAction::SEND_CODE);

        if ($caller === null) {
            return null;
        }

        $identity = $caller->identity;

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        $resolved = $this->drivers->resolve($registry, $driver);
        $result   = null;

        // A delivered code is sent bound to this session and purpose. Sending a
        // code resets no count and lifts no lockout: only a success of the
        // factor resets its failures in a row, so a resend cannot be used to
        // wipe a lockout. A TOTP factor has no per-challenge secret to mint, so
        // its `issueChallenge()` is a no-op.
        if ($resolved instanceof CodeDeliveryDriver) {
            $result = $this->container->make(CodeService::class)->send($identity, $factor, $this->binding($caller, $purpose), $resolved);
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
     *   the instance passed in: through the code service, against the code
     *   sent for this session and the purpose, for a driver that delivers
     *   codes; through the driver's verification logic otherwise.
     * - So a secret replaced in the meantime is the one checked, and a factor
     *   removed in the meantime is reported as not found without checking
     *   anything.
     * - Just before the code is checked, under that lock, the identity's
     *   verification generation is read, when it has a sign-in a proof can be
     *   recorded on, so a generation advanced while the code is checked leaves
     *   the proof behind.
     * - On success, inside the same transaction: a delivered code is used up
     *   and the factor's last use stamped, so they commit with the count and
     *   two requests with the same code cannot both pass.
     * - Once the code is checked, the instance passed in is brought up to date
     *   with the stored factor. On success the proof is recorded on the
     *   identity's current sign-in through the bound proof store, for the
     *   purpose, and `MfaVerified` dispatched; on failure
     *   `MfaVerificationFailed` is dispatched with a machine-readable reason,
     *   `locked` for an attempt a lockout refused and `not_found` for a factor
     *   removed in the meantime.
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
        $caller = $this->callers()->resolve(PendingAction::VERIFY);

        if ($caller === null) {
            return false;
        }

        $identity = $caller->identity;

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        $events   = $this->container->make(Dispatcher::class);
        $resolved = $this->drivers->resolve($registry, $driver);

        return $this->makeAttempt($caller, $factor, $driver, $resolved, $code, $purpose, $events);
    }

    /**
     * Make the attempt to verify the code against the factor through the
     * resolved driver, for the purpose given, and apply what it found: bring
     * the factor up to date, record the proof on success, and dispatch the
     * outcome.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $resolved
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    private function makeAttempt(
        Caller $caller,
        Factor $factor,
        string $driver,
        FactorDriver $resolved,
        #[\SensitiveParameter] string $code,
        Purpose $purpose,
        Dispatcher $events,
    ): bool {
        $identity   = $caller->identity;
        $binding    = $resolved instanceof CodeDeliveryDriver ? $this->binding($caller, $purpose) : null;
        $verified   = $factor;
        $check      = null;
        $generation = null;

        // The current identity's own session makes the attempt, so the identity
        // is charged for it.
        $outcome = $this->container->make(AttemptService::class)->attempt(
            new Attempt($identity, $factor, $purpose, RequestIp::resolve($this->container)),
            function (?Factor $stored) use ($identity, $resolved, $binding, $code, &$verified, &$check, &$generation): bool {

                $verified   = $stored ?? $verified;
                $generation = $this->proofs->generationFor($identity);

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

        if ($outcome->passed && $generation !== null) {
            $this->recordProof($identity, $generation, $factor, $driver, $resolved, $purpose);
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
     * Record the proof a successful verification made on the identity's current
     * sign-in, for the purpose it was made for, stamped with the verification
     * generation read before the code was checked: an additional factor proof
     * on the factor's channel (see `Factors\FactorChannel`). A driver whose
     * channel cannot carry a factor proves nothing, and neither does a factor
     * whose identifier cannot name it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  int  $generation
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $resolved
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function recordProof(MultiFactorAuthenticatable $identity, int $generation, Factor $factor, string $driver, FactorDriver $resolved, Purpose $purpose): void
    {
        $identifier = $factor->getFactorIdentifier();
        $channel    = FactorChannel::of($factor, $resolved->channelKind());

        if ($channel === null || (!is_string($identifier) && !is_int($identifier))) {
            return;
        }

        $this->proofs->record($identity, $generation, ProofKind::ADDITIONAL_FACTOR, $driver, $channel, (string) $identifier, $purpose);
    }

    /**
     * Apply the post-verify side effects: dispatch `MfaVerified` on success, or
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
     */
    private function finalizeVerification(MultiFactorAuthenticatable $identity, Factor $factor, string $driver, bool $valid, ?CodeCheck $check, Dispatcher $events): void
    {
        if ($valid) {
            AfterStorageCommit::run($this->container, static fn () => $events->dispatch(new MfaVerified($identity, $factor, $driver)));

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
     * What a delivered code for the caller is bound to in this request: the
     * identity, the application, the session and the purpose. On a pending
     * session they are the pending session's own application and public id;
     * otherwise the current request's application and the Laravel session.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function binding(Caller $caller, Purpose $purpose): ProofBinding
    {
        return new ProofBinding(
            CurrentIdentity::typeOf($caller->identity),
            self::identityKey($caller->identity),
            $this->callers()->application($caller),
            $caller->pending?->sessionId ?? $this->container->make(Session::class)->getId(),
            $purpose,
        );
    }

    /**
     * The resolver of who the request serves.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContextResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function callers(): CallerContextResolver
    {
        return $this->container->make(CallerContextResolver::class);
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
}
