<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\Carbon;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Config\IntegerSetting;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Records and reads the current identity's verification through the bound
 * `MfaVerificationStore`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the store and config are read from. */
        private Container $container,
    ) {}

    /**
     * Determine whether the current identity has ever completed a successful
     * MFA verification (on any device tracked by the bound verification store).
     *
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function hasEverVerified(): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return false;
        }

        return $this->store()->lastVerifiedAt($identity) !== null;
    }

    /**
     * Determine whether the current identity's MFA verification has expired.
     * Returns true when no prior verification exists OR the recorded
     * verification is older than the configured expiry window.
     *
     * @param  ?int  $expiresAfter
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function hasExpired(?int $expiresAfter = null): bool
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return true;
        }

        $verifiedAt = $this->store()->lastVerifiedAt($identity);
        $window     = $expiresAfter ?? IntegerSetting::read(
            $this->container->make('config'),
            'mfa.default_expiry',
            default          : 20160,
            malformedFallback: 0,
        );

        // `verifiedAt === null` means no prior verification exists.
        // `window <= 0` is the documented "require verification on every
        // request" setting and treats any prior verification as expired.
        if ($verifiedAt === null || $window <= 0) {
            return true;
        }

        // A negative `elapsed` means `verifiedAt` is in the future (clock skew
        // or a malicious store write): treat as expired rather than trusting a
        // future-dated verification.
        $elapsed = $verifiedAt->diffInMinutes(Carbon::now(), false);

        return $elapsed < 0 || $elapsed > $window;
    }

    /**
     * Record that the current identity has completed a successful MFA
     * verification. Writes through to the bound verification store.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function markVerified(): void
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return;
        }

        $this->store()->markVerified($identity);
    }

    /**
     * Clear any stored verification timestamp for the current identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function forgetVerification(): void
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return;
        }

        $this->store()->forget($identity);
    }

    /**
     * Resolve the bound verification store.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): MfaVerificationStore
    {
        /** @var \SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore */
        return $this->container->make(MfaVerificationStore::class);
    }
}
