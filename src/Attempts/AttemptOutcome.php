<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

/**
 * How an attempt ended. Only a driver failure is counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AttemptOutcome
{
    /**
     * @param  bool  $passed
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @param  bool  $found
     * @param  bool  $counted
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  $caused
     */
    private function __construct(

        /** Whether the driver accepted the attempt. */
        public bool $passed,

        /** Lockout that refused the attempt before the driver ran. */
        public ?Lockout $lockout = null,

        /** Whether the factor was among the identity's stored factors. */
        public bool $found = true,

        /** Whether a failure was counted. */
        public bool $counted = true,

        /** Strictest lockout this failure caused. */
        public ?Lockout $caused = null,
    ) {}

    /**
     * @return self
     */
    public static function pass(): self
    {
        return new self(true);
    }

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Attempts\Lockout  $caused
     * @return self
     */
    public static function fail(?Lockout $caused = null): self
    {
        return new self(false, null, true, true, $caused);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Attempts\Lockout  $lockout
     * @return self
     */
    public static function refuse(Lockout $lockout): self
    {
        return new self(false, $lockout);
    }

    /**
     * The factor was removed concurrently or never the identity's.
     *
     * @return self
     */
    public static function notFound(): self
    {
        return new self(false, null, false);
    }

    /**
     * @return self
     */
    public static function uncounted(): self
    {
        return new self(false, null, true, false);
    }

    /**
     * @return bool
     */
    public function isFailed(): bool
    {
        return !$this->passed && $this->lockout === null && $this->found && $this->counted;
    }

    /**
     * @return bool
     */
    public function isNotFound(): bool
    {
        return !$this->found;
    }

    /**
     * @return bool
     */
    public function isRefused(): bool
    {
        return $this->lockout !== null;
    }

    /**
     * @return bool
     */
    public function causedLockout(): bool
    {
        return $this->caused !== null;
    }
}
