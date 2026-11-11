<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckOutcome::class)]
final class CheckOutcomeTest extends TestCase
{
    /**
     * Holds what it observed, the challenge and the codes remaining.
     *
     * @return void
     */
    public function testAPass(): void
    {
        $properties = ObservedProperties::none();
        $outcome    = CheckOutcome::passed($properties, 'challenge-1', 4);

        self::assertTrue($outcome->hasPassed());
        self::assertTrue($outcome->counted);
        self::assertSame($properties, $outcome->properties);
        self::assertSame('challenge-1', $outcome->challengeId);
        self::assertSame(4, $outcome->remaining);
        self::assertNull(CheckOutcome::passed($properties)->challengeId);
        self::assertNull(CheckOutcome::passed($properties)->remaining);
    }

    /**
     * A failure was counted, and a refusal was not.
     *
     * @return void
     */
    public function testAFailureAndARefusal(): void
    {
        $failed = CheckOutcome::failed(FailureReason::INVALID_CODE, 'No.');

        self::assertFalse($failed->hasPassed());
        self::assertTrue($failed->counted);
        self::assertSame(FailureReason::INVALID_CODE, $failed->reason);
        self::assertSame('No.', $failed->detail);

        $until   = CarbonImmutable::parse('2026-11-01 12:00:00');
        $refused = CheckOutcome::refused(FailureReason::LOCKED, 'Locked.', $until);

        self::assertFalse($refused->counted);
        self::assertSame($until, $refused->lockedUntil);
    }

    /**
     * With the time of a lockout that has one.
     *
     * @return void
     */
    public function testAnAdmissionsRefusalCarriesOver(): void
    {
        $until = CarbonImmutable::parse('2026-11-01 12:00:00');

        $locked = CheckOutcome::refusedBy(ChallengeAdmission::locked(Lockout::endingAt(AttemptScope::FACTOR, $until)));

        self::assertSame(FailureReason::LOCKED, $locked->reason);
        self::assertSame($until, $locked->lockedUntil);
        self::assertFalse($locked->counted);

        $refused = CheckOutcome::refusedBy(ChallengeAdmission::refuse(FailureReason::NOT_CONFIRMED, 'Pending.'));

        self::assertSame(FailureReason::NOT_CONFIRMED, $refused->reason);
        self::assertSame('Pending.', $refused->detail);
        self::assertNull($refused->lockedUntil);
    }
}
