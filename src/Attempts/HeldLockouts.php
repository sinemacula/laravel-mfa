<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Models\IdentityState;

/**
 * Reads the lockouts the identity's state row and the factor as stored hold:
 * what refuses an attempt before the verification is called.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HeldLockouts
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The strictest lockout that refuses an attempt against the factor as
     * stored: the identity's run at the failure ceiling when the attempt names
     * no factor of its own, the identity's lockout, and the factor's.
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
     * The identity's lockout, while it is live.
     *
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
     * The identity's run of failures at the failure ceiling, which refuses an
     * attempt that names no factor of its own.
     *
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
     * The factor's lockout: disabled at the failure ceiling, or locked by its
     * failures in a row while that lockout is live. It is read off the instance
     * given, so the row as locked answers for an attempt.
     *
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
