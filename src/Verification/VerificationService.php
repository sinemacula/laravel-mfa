<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\Carbon;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Enums\MfaVerificationFailureReason;
use SineMacula\Laravel\Mfa\Events\MfaChallengeIssued;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\Factors\FactorOwnership;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
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
     * the requested driver name does not match the factor's own `getDriver()`:
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
     * - Runs the driver's verification logic.
     * - On success: resets attempts, stamps the factor's verified-at, clears
     *   any pending code, records the identity-level verification through the
     *   bound store, dispatches `MfaVerified`.
     * - On failure: increments attempts, applies a lockout once the configured
     *   per-driver threshold is reached, dispatches `MfaVerificationFailed`
     *   with a machine-readable reason.
     *
     * Throws `FactorOwnershipMismatchException` when the supplied factor does
     * not belong to the current identity, closing the cross-account MFA-bypass
     * primitive. Throws `FactorDriverMismatchException` when the requested
     * driver name does not match the factor's own `getDriver()`.
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
            $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, MfaVerificationFailureReason::FACTOR_LOCKED));

            return false;
        }

        $valid = $this->drivers->resolve($registry, $driver)->verify($factor, $code);

        if ($factor instanceof EloquentFactor) {
            $this->applyVerificationOutcome($factor, $driver, $valid);
        }

        $this->finalizeVerification($identity, $factor, $driver, $valid, $events);

        return $valid;
    }

    /**
     * Persist the post-driver verification outcome on the factor row.
     *
     * Successful verification stamps `verified_at`, resets attempts, and clears
     * any pending OTP code; failure increments the attempt counter and applies
     * a per-driver lockout once the configured threshold is crossed.
     * Non-Eloquent factors carry no row to mutate and skip both branches before
     * this method is even called.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $driver
     * @param  bool  $valid
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function applyVerificationOutcome(EloquentFactor $factor, string $driver, bool $valid): void
    {
        if ($valid) {
            $factor->recordVerification();
            $factor->persist();

            return;
        }

        $factor->recordAttempt();

        $config      = $this->container->make('config');
        $maxAttempts = IntegerSetting::read($config, 'mfa.drivers.' . $driver . '.max_attempts', 0);

        if ($maxAttempts > 0 && $factor->getAttempts() >= $maxAttempts) {
            $factor->applyLockout(
                Carbon::now()->addMinutes(IntegerSetting::read($config, 'mfa.lockout_minutes', 15)),
            );
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
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function finalizeVerification(MultiFactorAuthenticatable $identity, Factor $factor, string $driver, bool $valid, Dispatcher $events): void
    {
        if ($valid) {
            /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore $store */
            $store = $this->container->make(MfaVerificationStore::class);
            $store->markVerified($identity);
            $this->cache->clear($identity);

            $events->dispatch(new MfaVerified($identity, $factor, $driver));

            return;
        }

        // Classify the failure inline. Branches in priority order:
        // SECRET_MISSING when TOTP enrolment never completed (no code and no
        // secret); CODE_EXPIRED when the pending OTP aged past its window;
        // CODE_MISSING when a pending code exists but has no expiry - treat as
        // missing; CODE_INVALID otherwise - TOTP window mismatch or OTP
        // comparison mismatch.
        $expiresAt = $factor->getExpiresAt();
        $pending   = $factor->getCode();
        $secret    = $factor->getSecret();

        $reason = match (true) {
            $pending === null   && $secret === null     => MfaVerificationFailureReason::SECRET_MISSING,
            $expiresAt !== null && $expiresAt->isPast() => MfaVerificationFailureReason::CODE_EXPIRED,
            $pending   !== null && $expiresAt === null  => MfaVerificationFailureReason::CODE_MISSING,
            default                                     => MfaVerificationFailureReason::CODE_INVALID,
        };

        $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, $reason));
    }
}
