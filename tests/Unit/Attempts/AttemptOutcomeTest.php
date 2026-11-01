<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\AttemptOutcome;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;

/**
 * Unit tests for `AttemptOutcome`: an attempt passed, failed or refused, each
 * told apart from the others.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptOutcome::class)]
final class AttemptOutcomeTest extends TestCase
{
    /**
     * A passed attempt is neither failed nor refused.
     *
     * @return void
     */
    public function testAPassedAttempt(): void
    {
        $outcome = AttemptOutcome::pass();

        self::assertTrue($outcome->passed);
        self::assertNull($outcome->lockout);
        self::assertFalse($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
    }

    /**
     * A failed attempt is counted, and was not refused.
     *
     * @return void
     */
    public function testAFailedAttempt(): void
    {
        $outcome = AttemptOutcome::fail();

        self::assertFalse($outcome->passed);
        self::assertNull($outcome->lockout);
        self::assertTrue($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
    }

    /**
     * A refused attempt carries its lockout, and is not a counted failure.
     *
     * @return void
     */
    public function testARefusedAttempt(): void
    {
        $lockout = Lockout::endingAt(AttemptScope::IP, CarbonImmutable::parse('2026-11-01 12:15:00'));
        $outcome = AttemptOutcome::refuse($lockout);

        self::assertFalse($outcome->passed);
        self::assertSame($lockout, $outcome->lockout);
        self::assertFalse($outcome->isFailed());
        self::assertTrue($outcome->isRefused());
    }
}
