<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Why an attempt is refused before it reaches the driver. With no end time it
 * is a failure-ceiling hold that only a success, rebind or reset clears.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Lockout
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  ?\Carbon\CarbonImmutable  $until
     */
    private function __construct(

        /** What is locked. */
        public AttemptScope $scope,

        /** Null at the failure ceiling. */
        public ?CarbonImmutable $until,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @param  \Carbon\CarbonImmutable  $until
     * @return self
     */
    public static function endingAt(AttemptScope $scope, CarbonImmutable $until): self
    {
        return new self($scope, $until);
    }

    /**
     * Read in the application's timezone.
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
     * @param  \SineMacula\Laravel\Mfa\Enums\AttemptScope  $scope
     * @return self
     */
    public static function disabled(AttemptScope $scope = AttemptScope::FACTOR): self
    {
        return new self($scope, null);
    }

    /**
     * A failure-ceiling hold wins; otherwise the one that ends last.
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
     * @return bool
     */
    public function isDisabled(): bool
    {
        return $this->until === null;
    }

    /**
     * For events and logs only.
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
