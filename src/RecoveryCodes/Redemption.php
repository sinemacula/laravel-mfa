<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * A recovery code redemption that passed, failed as a counted attempt, or was
 * refused before any attempt; the detail never holds the submitted code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Redemption
{
    /**
     * @param  bool  $passed
     * @param  bool  $counted
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?int  $remaining
     */
    private function __construct(

        /** Whether a code was redeemed. */
        public bool $passed,

        /** Whether it counted as an attempt. */
        public bool $counted,

        /** Null when passed. */
        public ?FailureReason $reason = null,

        /** For events and logs only. */
        public ?string $detail = null,

        /** For `locked` only; null at the failure ceiling, which only a success or reset clears. */
        public ?CarbonImmutable $lockedUntil = null,

        /** Unused codes when the set was read; null when it was not read. */
        public ?int $remaining = null,
    ) {}

    /**
     * @param  int  $remaining
     * @return self
     */
    public static function passed(int $remaining): self
    {
        return new self(passed: true, counted: true, remaining: $remaining);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?int  $remaining
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function failed(FailureReason $reason, string $detail, ?int $remaining = null): self
    {
        self::assertFailure($reason, $detail);

        if ($reason === FailureReason::LOCKED) {
            throw new \InvalidArgumentException('A lockout refuses a redemption before it is counted.');
        }

        return new self(passed: false, counted: true, reason: $reason, detail: $detail, remaining: $remaining);
    }

    /**
     * Refused before any attempt was made, so not counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function refused(FailureReason $reason, string $detail, ?CarbonImmutable $lockedUntil = null): self
    {
        self::assertFailure($reason, $detail);

        if ($reason !== FailureReason::LOCKED && $lockedUntil !== null) {
            throw new \InvalidArgumentException(sprintf('Only a failure of reason [locked] carries the time a lockout lifts, not [%s].', $reason->value));
        }

        return new self(passed: false, counted: false, reason: $reason, detail: $detail, lockedUntil: $lockedUntil);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertFailure(FailureReason $reason, string $detail): void
    {
        if (trim($detail) === '') {
            throw new \InvalidArgumentException(sprintf('The detail of a failed redemption of reason [%s] must not be blank.', $reason->value));
        }
    }
}
