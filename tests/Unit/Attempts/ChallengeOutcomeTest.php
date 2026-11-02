<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Unit tests for `ChallengeOutcome`: passed, failed and counted, or refused and
 * counted nowhere.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeOutcome::class)]
final class ChallengeOutcomeTest extends TestCase
{
    /**
     * A pass has no reason and was counted.
     *
     * @return void
     */
    public function testAPass(): void
    {
        $outcome = ChallengeOutcome::passed();

        self::assertTrue($outcome->hasPassed());
        self::assertTrue($outcome->counted);
        self::assertNull($outcome->reason);
        self::assertNull($outcome->lockedUntil);
    }

    /**
     * A failure carries its reason and detail, and was counted.
     *
     * @return void
     */
    public function testAFailure(): void
    {
        $outcome = ChallengeOutcome::failed(FailureReason::INVALID_CODE, 'The code did not match.');

        self::assertFalse($outcome->hasPassed());
        self::assertTrue($outcome->counted);
        self::assertSame(FailureReason::INVALID_CODE, $outcome->reason);
        self::assertSame('The code did not match.', $outcome->detail);
        self::assertNull($outcome->lockedUntil);
    }

    /**
     * A refusal was counted nowhere, and a lockout says when it ends if it
     * does.
     *
     * @return void
     */
    public function testARefusal(): void
    {
        $until   = CarbonImmutable::parse('2026-11-01 12:00:00');
        $outcome = ChallengeOutcome::refused(FailureReason::LOCKED, 'Locked.', $until);

        self::assertFalse($outcome->hasPassed());
        self::assertFalse($outcome->counted);
        self::assertSame(FailureReason::LOCKED, $outcome->reason);
        self::assertSame('Locked.', $outcome->detail);
        self::assertSame($until, $outcome->lockedUntil);
        self::assertNull(ChallengeOutcome::refused(FailureReason::NOT_FOUND, 'Gone.')->lockedUntil);
    }
}
