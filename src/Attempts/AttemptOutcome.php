<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

/**
 * How an attempt ended: passed, failed (and counted), refused before it reached
 * the driver by the lockout it names (and counted nowhere), not found, when the
 * factor it names is not among the identity's factors as stored (and counted
 * nowhere either), or refused for any other reason, counted nowhere. A failure
 * that was counted names the lockout it caused, if counting it locked or
 * disabled what the next attempt would name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptOutcome
{
    /**
     * Constructor.
     *
     * @param  bool  $passed
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @param  bool  $found
     * @param  bool  $counted
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  $caused
     */
    private function __construct(

        /** Whether the driver accepted the attempt. */
        public bool $passed,

        /** The lockout that refused the attempt before the driver ran, if one did. */
        public ?Lockout $lockout = null,

        /** Whether the factor the attempt names was found among the identity's stored factors. */
        public bool $found = true,

        /** Whether an attempt that did not pass was counted as a failure. */
        public bool $counted = true,

        /** The strictest lockout that counting this failure applied, if it applied one. */
        public ?Lockout $caused = null,
    ) {}

    /**
     * An attempt the driver accepted.
     *
     * @return self
     */
    public static function pass(): self
    {
        return new self(true);
    }

    /**
     * An attempt the driver refused, counted against every scope it charges,
     * with the strictest lockout counting it applied, if any.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  $caused
     * @return self
     */
    public static function fail(?Lockout $caused = null): self
    {
        return new self(false, null, true, true, $caused);
    }

    /**
     * An attempt refused by a lockout before the driver ran.
     *
     * @param  \SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @return self
     */
    public static function refuse(Lockout $lockout): self
    {
        return new self(false, $lockout);
    }

    /**
     * An attempt whose factor is not among the identity's factors as stored
     * under the lock: removed by a concurrent change, or never the identity's.
     * The driver is not called.
     *
     * @return self
     */
    public static function notFound(): self
    {
        return new self(false, null, false);
    }

    /**
     * An attempt refused for a reason other than a lockout or a missing factor,
     * counted nowhere.
     *
     * @return self
     */
    public static function uncounted(): self
    {
        return new self(false, null, true, false);
    }

    /**
     * Determine whether the driver refused the attempt, which was counted.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return !$this->passed && $this->lockout === null && $this->found && $this->counted;
    }

    /**
     * Determine whether the factor the attempt names was not found.
     *
     * @return bool
     */
    public function isNotFound(): bool
    {
        return !$this->found;
    }

    /**
     * Determine whether a lockout refused the attempt before the driver ran.
     *
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->lockout !== null;
    }

    /**
     * Determine whether counting the failure locked or disabled what the next
     * attempt would name.
     *
     * @return bool
     */
    public function causedLockout(): bool
    {
        return $this->caused !== null;
    }
}
