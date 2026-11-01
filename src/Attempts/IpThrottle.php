<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * The throttle on the IP address an attempt came from: its failures within the
 * window, across every identity, refused until the window ends once they reach
 * the IP limit.
 *
 * A slot is taken from the address's window in one statement before the attempt
 * is made, so parallel guesses from one address cannot overrun its cap, and
 * given back unless the attempt fails, so only failures are counted. An attempt
 * made outside a request has no address and is not throttled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IpThrottle
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptStore  $store
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptKeys  $keys
     */
    public function __construct(

        /** The throttle rows. */
        private AttemptStore $store,

        /** The keys the throttle rows are stored under. */
        private AttemptKeys $keys,
    ) {}

    /**
     * Take a slot of the IP address's window: the key and the window the slot
     * came from, to give it back with, or the lockout when the window is full.
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
     * Give back the slot `take()` returned, if one was taken.
     *
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
     * The IP address's throttle, while its window is live and full, or `null`
     * when none applies.
     *
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
