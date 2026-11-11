<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Models\IdentityState;

/**
 * Lockouts held on the identity state row and the stored factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HeldLockouts
{
    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * The identity's failure ceiling applies only to an attempt with no factor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     */
    public static function strictest(?IdentityState $state, (EloquentFactor&Model)|null $factor, AttemptSettings $settings, CarbonImmutable $now): ?Lockout
    {
        return Lockout::strictest(
            $factor === null ? self::identityCeiling($state, $settings) : null,
            self::identity($state, $now),
            self::factor($factor, $now),
        );
    }

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     */
    public static function identity(?IdentityState $state, CarbonImmutable $now): ?Lockout
    {
        $until = $state?->locked_until;

        return $until !== null && $until->getTimestamp() > $now->getTimestamp()
            ? Lockout::endingAt(AttemptScope::IDENTITY, CarbonImmutable::instance($until))
            : null;
    }

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Models\IdentityState  $state
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     */
    public static function identityCeiling(?IdentityState $state, AttemptSettings $settings): ?Lockout
    {
        return $state !== null && $state->consecutive_failures >= $settings->failureCeiling() ? Lockout::disabled(AttemptScope::IDENTITY) : null;
    }

    /**
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor)|null  $factor
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     */
    public static function factor((EloquentFactor&Model)|null $factor, CarbonImmutable $now): ?Lockout
    {
        if ($factor === null) {
            return null;
        }

        if ($factor->getDisabledAt() !== null) {
            return Lockout::disabled();
        }

        $until = $factor->getLockedUntil();

        return $until !== null && $until->getTimestamp() > $now->getTimestamp()
            ? Lockout::endingAt(AttemptScope::FACTOR, CarbonImmutable::instance($until))
            : null;
    }
}
