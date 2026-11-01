<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\Carbon;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Attempts\AttemptSettings;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Issues challenges for the current identity's factors and verifies the codes
 * submitted against them.
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

        /** The container the dispatcher and config are read from. */
        private Container $container,

        /** The resolver of the factor drivers. */
        private DriverResolver $drivers,

        /** The recorder of the proofs a verification makes. */
        private ProofService $proofs,
    ) {}

    /**
     * Issue a challenge for the given factor through the named driver.
     *
     * Dispatches `MfaChallengeIssued` after delegating to the driver's
     * `issueChallenge()` implementation: for delivery drivers (email, SMS) the
     * challenge is sent; for implicit drivers (TOTP) this is a signal that a
     * verification window is now active.
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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function challenge(Manager $registry, string $driver, Factor $factor): void
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return;
        }

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        // OTP-issuing drivers (email, SMS) reset the attempt counter and
        // persist the freshly minted code from inside `issueChallenge()`: the
        // reset is paired with a fresh secret and so cannot be used to wipe a
        // lockout without rotating credentials. TOTP and backup codes have no
        // per-challenge secret to mint and no state to persist, so their
        // `issueChallenge()` is a no-op and their lockout state is preserved
        // across challenge calls.
        $this->drivers->resolve($registry, $driver)->issueChallenge($factor);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaChallengeIssued($identity, $factor, $driver));
    }

    /**
     * Verify a submitted code against the given factor through the named
     * driver.
     *
     * - Rejects the attempt when the factor is locked.
     * - Reads the identity's verification generation, when it has a sign-in a
     *   proof can be recorded on, before the driver runs, so a generation
     *   advanced while the code is checked leaves the proof behind.
     * - Runs the driver's verification logic.
     * - On success: resets attempts, stamps the factor's last use, clears any
     *   pending code, records the proof on the identity's current sign-in
     *   through the bound proof store, dispatches `MfaVerified`.
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
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public function verify(Manager $registry, string $driver, Factor $factor, #[\SensitiveParameter] string $code): bool
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

        $generation = $this->proofs->generationFor($identity);
        $resolved   = $this->drivers->resolve($registry, $driver);
        $valid      = $resolved->verify($factor, $code);

        if ($factor instanceof EloquentFactor) {
            $this->applyVerificationOutcome($factor, $valid);
        }

        if ($valid && $generation !== null) {
            $this->recordProof($identity, $generation, $factor, $driver, $resolved);
        }

        $this->finalizeVerification($identity, $factor, $driver, $valid, $events);

        return $valid;
    }

    /**
     * Persist the post-driver verification outcome on the factor row.
     *
     * Successful verification stamps `last_used_at`, resets attempts, and
     * clears any pending OTP code; failure increments the attempt counter and,
     * once it reaches `mfa.attempts.factor_limit`, locks the factor for
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
     * Record the proof a successful verification made on the identity's current
     * sign-in, stamped with the verification generation read before the code
     * was checked: a recovery code proof for a backup code, which travels on no
     * channel, and an additional factor proof on the factor's channel
     * otherwise, named by the factor's destination when it has one and by the
     * factor itself when not. A driver whose channel cannot carry a factor
     * proves nothing, and neither does a factor whose identifier cannot name
     * it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  int  $generation
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $driver
     * @param  \SineMacula\Laravel\Mfa\Contracts\FactorDriver  $resolved
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function recordProof(MultiFactorAuthenticatable $identity, int $generation, Factor $factor, string $driver, FactorDriver $resolved): void
    {
        if ($resolved instanceof BackupCodeDriver) {
            $this->proofs->record($identity, $generation, ProofKind::RECOVERY_CODE, $driver, null, null, Purpose::STEP_UP);

            return;
        }

        $identifier = $factor->getFactorIdentifier();
        $kind       = $resolved->channelKind();

        if (!$kind->carriesFactor() || (!is_string($identifier) && !is_int($identifier))) {
            return;
        }

        $reference = (string) $identifier;
        $channel   = new Channel($kind, $factor->getDestination() ?? $reference);

        $this->proofs->record($identity, $generation, ProofKind::ADDITIONAL_FACTOR, $driver, $channel, $reference, Purpose::STEP_UP);
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
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function finalizeVerification(MultiFactorAuthenticatable $identity, Factor $factor, string $driver, bool $valid, Dispatcher $events): void
    {
        if ($valid) {
            $events->dispatch(new MfaVerified($identity, $factor, $driver));

            return;
        }

        // Classify the failure inline. Branches in priority order: not
        // confirmed when TOTP enrolment never completed (no code and no
        // secret); expired when the pending code aged past its window, or when
        // a pending code has no expiry, so no live code exists; an invalid code
        // otherwise - a TOTP window mismatch or an OTP comparison mismatch. The
        // detail keeps the two expired cases apart.
        $expiresAt = $factor->getExpiresAt();
        $pending   = $factor->getCode();
        $secret    = $factor->getSecret();

        [$reason, $detail] = match (true) {
            $pending === null   && $secret === null     => [FailureReason::NOT_CONFIRMED, 'The factor has no pending code or secret, so its enrolment never completed.'],
            $expiresAt !== null && $expiresAt->isPast() => [FailureReason::EXPIRED, 'The pending code has expired.'],
            $pending   !== null && $expiresAt === null  => [FailureReason::EXPIRED, 'The pending code has no expiry, so no live code exists.'],
            default                                     => [FailureReason::INVALID_CODE, 'The code did not match.'],
        };

        $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, $reason, $detail));
    }
}
