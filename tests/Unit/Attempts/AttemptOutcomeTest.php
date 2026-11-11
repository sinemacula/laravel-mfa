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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttemptOutcome::class)]
final class AttemptOutcomeTest extends TestCase
{
    /**
     * @return void
     */
    public function testAPassedAttempt(): void
    {
        $outcome = AttemptOutcome::pass();

        self::assertTrue($outcome->passed);
        self::assertNull($outcome->lockout);
        self::assertFalse($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
        self::assertFalse($outcome->isNotFound());
    }

    /**
     * @return void
     */
    public function testAFailedAttempt(): void
    {
        $outcome = AttemptOutcome::fail();

        self::assertFalse($outcome->passed);
        self::assertNull($outcome->lockout);
        self::assertNull($outcome->caused);
        self::assertTrue($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
        self::assertFalse($outcome->isNotFound());
        self::assertFalse($outcome->causedLockout());
    }

    /**
     * It names the lockout it caused, and is still a counted failure that no
     * lockout refused.
     *
     * @return void
     */
    public function testAFailureThatCausedALockout(): void
    {
        $lockout = Lockout::endingAt(AttemptScope::FACTOR, CarbonImmutable::parse('2026-11-01 12:15:00'));
        $outcome = AttemptOutcome::fail($lockout);

        self::assertSame($lockout, $outcome->caused);
        self::assertNull($outcome->lockout);
        self::assertTrue($outcome->causedLockout());
        self::assertTrue($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
    }

    /**
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
        self::assertFalse($outcome->isNotFound());
    }

    /**
     * It neither passed nor counted, and was not refused by a lockout.
     *
     * @return void
     */
    public function testAnAttemptOnAFactorNotFound(): void
    {
        $outcome = AttemptOutcome::notFound();

        self::assertFalse($outcome->passed);
        self::assertNull($outcome->lockout);
        self::assertFalse($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
        self::assertTrue($outcome->isNotFound());
    }

    /**
     * Refused for any other reason, it neither passed nor counted, and is
     * neither a lockout nor a factor not found.
     *
     * @return void
     */
    public function testAnUncountedAttempt(): void
    {
        $outcome = AttemptOutcome::uncounted();

        self::assertFalse($outcome->passed);
        self::assertFalse($outcome->counted);
        self::assertFalse($outcome->isFailed());
        self::assertFalse($outcome->isRefused());
        self::assertFalse($outcome->isNotFound());
        self::assertTrue(AttemptOutcome::fail()->counted);
    }
}
