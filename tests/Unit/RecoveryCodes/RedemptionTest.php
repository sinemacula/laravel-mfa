<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\RecoveryCodes\Redemption;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Redemption::class)]
final class RedemptionTest extends TestCase
{
    /**
     * Counted, with the remaining count and nothing about a failure.
     *
     * @return void
     */
    public function testAPassedRedemption(): void
    {
        $redemption = Redemption::passed(7);

        self::assertTrue($redemption->passed);
        self::assertTrue($redemption->counted);
        self::assertSame(7, $redemption->remaining);
        self::assertNull($redemption->reason);
        self::assertNull($redemption->detail);
        self::assertNull($redemption->lockedUntil);
    }

    /**
     * Counted, with its reason, detail and the remaining count when the set was
     * read, and no time.
     *
     * @return void
     */
    public function testAFailedRedemption(): void
    {
        $redemption = Redemption::failed(FailureReason::INVALID_CODE, 'No code matched.', 4);

        self::assertFalse($redemption->passed);
        self::assertTrue($redemption->counted);
        self::assertSame(FailureReason::INVALID_CODE, $redemption->reason);
        self::assertSame('No code matched.', $redemption->detail);
        self::assertSame(4, $redemption->remaining);
        self::assertNull($redemption->lockedUntil);
        self::assertNull(Redemption::failed(FailureReason::NO_FACTOR, 'Gone.')->remaining);
    }

    /**
     * Not counted and never read the set; a lockout carries the time it lifts,
     * or none at the failure ceiling.
     *
     * @return void
     */
    public function testARefusedRedemption(): void
    {
        $until      = CarbonImmutable::parse('2026-11-01 12:00:00');
        $redemption = Redemption::refused(FailureReason::LOCKED, 'Locked.', $until);

        self::assertFalse($redemption->passed);
        self::assertFalse($redemption->counted);
        self::assertSame(FailureReason::LOCKED, $redemption->reason);
        self::assertSame('Locked.', $redemption->detail);
        self::assertSame($until, $redemption->lockedUntil);
        self::assertNull($redemption->remaining);
        self::assertNull(Redemption::refused(FailureReason::LOCKED, 'At the ceiling.')->lockedUntil);
        self::assertSame(FailureReason::NOT_ACCEPTED, Redemption::refused(FailureReason::NOT_ACCEPTED, 'Enrolment.')->reason);
    }

    /**
     * Whether failed or refused.
     *
     * @return void
     */
    public function testABlankDetailIsRefused(): void
    {
        foreach ([static fn () => Redemption::failed(FailureReason::INVALID_CODE, ' '), static fn () => Redemption::refused(FailureReason::NO_FACTOR, '')] as $build) {

            try {
                $build();
                self::fail('A blank detail was expected to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringEndsWith('must not be blank.', $exception->getMessage());
            }
        }
    }

    /**
     * @return void
     */
    public function testOnlyALockoutCarriesATimeAndIsNeverCounted(): void
    {
        try {
            Redemption::refused(FailureReason::INVALID_CODE, 'No match.', CarbonImmutable::now());
            self::fail('A time on a failure other than a lockout was expected to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Only a failure of reason [locked] carries the time a lockout lifts, not [invalid_code].', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A lockout refuses a redemption before it is counted.');

        Redemption::failed(FailureReason::LOCKED, 'Locked.');
    }
}
