<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Per-IP failure throttle across identities. A slot is taken atomically before
 * the attempt, so parallel guesses cannot overrun the cap, and given back
 * unless the attempt fails.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IpThrottle
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptStore  $store
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptKeys  $keys
     */
    public function __construct(

        /** Throttle rows. */
        private AttemptStore $store,

        /** Row keys. */
        private AttemptKeys $keys,
    ) {}

    /**
     * Returns the slot to give back, or the lockout when the window is full.
     * Nothing is taken without an address.
     *
     * @param  ?string  $ip
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @return array{0: string, 1: string}|\SineMacula\Laravel\Mfa\Attempts\Lockout|null
     *
     * @throws \InvalidArgumentException
     */
    public function take(?string $ip, AttemptSettings $settings): array|Lockout|null
    {
        if ($ip === null || $ip === '') {
            return null;
        }

        $key    = $this->keys->ip($ip);
        $now    = CarbonImmutable::now()->getTimestamp();
        $window = $this->store->take($key, AttemptScope::IP, $settings->ipLimit(), $now, $now + $settings->windowSeconds());

        return is_int($window) ? Lockout::endingAtTimestamp(AttemptScope::IP, $window) : [$key, $window];
    }

    /**
     * @param  array{0: string, 1: string}|null  $slot
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function giveBack(?array $slot): void
    {
        if ($slot === null) {
            return;
        }

        $this->store->giveBack($slot[0], $slot[1]);
    }

    /**
     * @param  ?string  $ip
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptSettings  $settings
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Mfa\Attempts\Lockout
     *
     * @throws \InvalidArgumentException
     */
    public function lockout(?string $ip, AttemptSettings $settings, CarbonImmutable $now): ?Lockout
    {
        if ($ip === null || $ip === '') {
            return null;
        }

        $key = $this->keys->ip($ip);
        $row = $this->store->read([$key])[$key] ?? null;

        return $row !== null && $row['ends'] > $now->getTimestamp() && $row['hits'] >= $settings->ipLimit()
            ? Lockout::endingAtTimestamp(AttemptScope::IP, $row['ends'])
            : null;
    }
}
