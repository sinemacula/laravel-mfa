<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Why an attempt is refused before it reaches the driver: a factor locked by
 * its failures in a row, the identity locked by its failures within the window,
 * or the IP address throttled by its own, each until a time; or, with no time
 * to end at, a factor disabled at the failure ceiling, which only proving
 * another factor, rebinding it or a reset enables again, or an identity whose
 * run of failures reached the ceiling, which refuses every attempt that names
 * no factor of its own until a success or a reset clears the run.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Lockout
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  ?\Carbon\CarbonImmutable  $until
     */
    private function __construct(

        /** What is locked: the factor, the identity or the IP address. */
        public AttemptScope $scope,

        /** When the lockout ends, or null for a factor or an identity at the failure ceiling. */
        public ?CarbonImmutable $until,
    ) {}

    /**
     * A lockout of the scope that ends at the given time.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  \Carbon\CarbonImmutable  $until
     * @return self
     */
    public static function endingAt(AttemptScope $scope, CarbonImmutable $until): self
    {
        return new self($scope, $until);
    }

    /**
     * A lockout of the scope that ends at the given Unix time, read in the
     * application's timezone.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  int  $timestamp
     * @return self
     */
    public static function endingAtTimestamp(AttemptScope $scope, int $timestamp): self
    {
        return new self($scope, CarbonImmutable::createFromTimestamp($timestamp, date_default_timezone_get()));
    }

    /**
     * A factor disabled at the failure ceiling, or, given the identity scope,
     * an identity whose run of failures reached it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @return self
     */
    public static function disabled(AttemptScope $scope = AttemptScope::FACTOR): self
    {
        return new self($scope, null);
    }

    /**
     * The strictest of the lockouts given: one at the failure ceiling first,
     * otherwise the lockout that ends last, or `null` when none is given.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  ...$lockouts
     * @return ?self
     */
    public static function strictest(?self ...$lockouts): ?self
    {
        $strictest = null;
        $latest    = null;

        foreach (array_filter($lockouts) as $lockout) {

            $until = $lockout->until;

            if ($until === null) {
                return $lockout;
            }

            if ($latest !== null && $until->lessThanOrEqualTo($latest)) {
                continue;
            }

            $strictest = $lockout;
            $latest    = $until;
        }

        return $strictest;
    }

    /**
     * Determine whether this is a factor or an identity at the failure ceiling,
     * rather than a lockout that ends on its own.
     *
     * @return bool
     */
    public function isDisabled(): bool
    {
        return $this->until === null;
    }

    /**
     * What is refused and why, for events and logs only.
     *
     * @return string
     */
    public function detail(): string
    {
        if ($this->until === null) {
            return $this->scope === AttemptScope::IDENTITY
                ? 'The identity has reached the failure ceiling across its factors and recovery codes.'
                : 'The factor is disabled after reaching the failure ceiling.';
        }

        return match (true) {
            $this->scope === AttemptScope::FACTOR   => 'The factor is locked after too many failed attempts.',
            $this->scope === AttemptScope::IDENTITY => 'The identity is locked after too many failed attempts across its factors.',
            default                                 => 'The IP address is throttled after too many failed attempts.',
        };
    }
}
