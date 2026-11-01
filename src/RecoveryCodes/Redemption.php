<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * How a recovery code redemption ended: passed, with how many codes remain and
 * the proof it recorded; failed, counted against the identity and the address
 * as an attempt; or refused before any attempt was made, counted nowhere.
 *
 * A failure carries the reason a caller may be told and a detail for events and
 * logs only, never the submitted code. A lockout carries the time it lifts, or
 * none when the identity's run of failures has reached the failure ceiling,
 * which only a success or a reset clears; no other failure carries a time.
 * `remaining` is how many codes were unused when the set was read, and is
 * `null` when the set was never read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Redemption
{
    /**
     * Constructor.
     *
     * @param  bool  $passed
     * @param  bool  $counted
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  ?int  $remaining
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     */
    private function __construct(

        /** Whether a code was redeemed. */
        public bool $passed,

        /** Whether the redemption was counted as an attempt. */
        public bool $counted,

        /** Why the redemption failed, when it did. */
        public ?FailureReason $reason = null,

        /** What happened in detail, for events and logs only, when it failed. */
        public ?string $detail = null,

        /** When the lockout lifts, for `locked` only, and never at the failure ceiling. */
        public ?CarbonImmutable $lockedUntil = null,

        /** How many codes were unused when the set was read, or null when it was not. */
        public ?int $remaining = null,

        /** The proof the redemption recorded, when it passed. */
        public ?Proof $proof = null,
    ) {}

    /**
     * A redemption that used a code, leaving the given number unused, with the
     * proof it recorded.
     *
     * @param  int  $remaining
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return self
     */
    public static function passed(int $remaining, ?Proof $proof = null): self
    {
        return new self(passed: true, counted: true, remaining: $remaining, proof: $proof);
    }

    /**
     * A redemption counted as a failed attempt.
     *
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
     * A redemption refused before any attempt was made, counted nowhere; a
     * lockout with the time it lifts, if it lifts on its own.
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
     * Refuse a blank detail.
     *
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
