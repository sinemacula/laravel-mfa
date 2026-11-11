<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeAdmission::class)]
final class ChallengeAdmissionTest extends TestCase
{
    /**
     * @return void
     */
    public function testAdmits(): void
    {
        $admission = ChallengeAdmission::admit();

        self::assertTrue($admission->isAdmitted());
        self::assertNull($admission->reason);
        self::assertNull($admission->lockedUntil);
    }

    /**
     * None at the failure ceiling.
     *
     * @return void
     */
    public function testLocks(): void
    {
        $until  = CarbonImmutable::parse('2026-11-01T12:15:00+00:00');
        $locked = ChallengeAdmission::locked(Lockout::endingAt(AttemptScope::FACTOR, $until));

        self::assertFalse($locked->isAdmitted());
        self::assertSame(FailureReason::LOCKED, $locked->reason);
        self::assertSame($until, $locked->lockedUntil);
        self::assertSame('The factor is locked after too many failed attempts.', $locked->detail);
        self::assertNull(ChallengeAdmission::locked(Lockout::disabled())->lockedUntil);
    }

    /**
     * @return void
     */
    public function testRefuses(): void
    {
        $refused = ChallengeAdmission::refuse(FailureReason::NOT_ACCEPTED, 'Not accepted.');

        self::assertFalse($refused->isAdmitted());
        self::assertSame(FailureReason::NOT_ACCEPTED, $refused->reason);
        self::assertNull($refused->lockedUntil);
        self::assertSame('Not accepted.', $refused->detail);
    }
}
