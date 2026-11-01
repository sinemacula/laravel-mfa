<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Manager;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
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

        // Sending a code resets no count and lifts no lockout: only a success
        // of the factor resets its failures in a row, so a resend cannot be
        // used to wipe a lockout.
        $this->drivers->resolve($registry, $driver)->issueChallenge($factor);

        $events = $this->container->make(Dispatcher::class);
        $events->dispatch(new MfaChallengeIssued($identity, $factor, $driver));
    }

    /**
     * Verify a submitted code against the given factor through the named
     * driver.
     *
     * - The attempt is made through the attempt service, charged to the
     *   current identity, the factor and the request's IP address: refused
     *   without reaching the driver while a lockout applies, otherwise counted
     *   with its outcome under the identity's factor state lock.
     * - On success: stamps the factor's verified-at, clears any pending code,
     *   records the identity-level verification through the bound store,
     *   dispatches `MfaVerified`.
     * - On failure: dispatches `MfaVerificationFailed` with a machine-readable
     *   reason, `locked` for an attempt a lockout refused.
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
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorDriverMismatchException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     * @throws \Throwable
     */
    public function verify(Manager $registry, string $driver, Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return false;
        }

        $this->drivers->assertMatchesFactor($driver, $factor);
        FactorOwnership::assert($factor, $identity);

        $events   = $this->container->make(Dispatcher::class);
        $resolved = $this->drivers->resolve($registry, $driver);

        // The current identity's own session makes the attempt, so the
        // identity is charged for it. This entry point takes no purpose of its
        // own, so its attempts are counted as sign-in.
        $outcome = $this->container->make(AttemptService::class)->attempt(
            new Attempt($identity, $factor, Purpose::SIGN_IN, $this->ip()),
            static fn (): bool => $resolved->verify($factor, $code),
        );

        if ($outcome->lockout !== null) {
            $events->dispatch(new MfaVerificationFailed($identity, $factor, $driver, FailureReason::LOCKED, $outcome->lockout->detail()));

            return false;
        }

        if ($outcome->passed && $factor instanceof EloquentFactor) {
            $factor->recordVerification();
            $factor->persist();
        }

        $this->finalizeVerification($identity, $factor, $driver, $outcome->passed, $events);

        return $outcome->passed;
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
