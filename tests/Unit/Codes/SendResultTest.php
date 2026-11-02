<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Attempts\Lockout;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Unit tests for `SendResult`: a sent code's challenge and expiry, and a
 * refusal's reason and wait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendResult::class)]
final class SendResultTest extends TestCase
{
    /**
     * A sent result names the challenge and when its code stops working, and no
     * reason or wait.
     *
     * @return void
     */
    public function testASentResultNamesTheChallengeAndExpiry(): void
    {
        $expiresAt = CarbonImmutable::parse('2026-11-01 12:10:00');
        $result    = SendResult::sent('challenge-1', $expiresAt);

        self::assertTrue($result->wasSent());
        self::assertSame('challenge-1', $result->challengeId);
        self::assertSame($expiresAt, $result->expiresAt);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
    }

    /**
     * A refusal names its reason and wait, and no challenge or expiry.
     *
     * @return void
     */
    public function testARefusalNamesItsReasonAndWait(): void
    {
        $result = SendResult::refused(FailureReason::SENDING_CAPPED, 42);

        self::assertFalse($result->wasSent());
        self::assertSame(FailureReason::SENDING_CAPPED, $result->reason);
        self::assertSame(42, $result->retryAfter);
        self::assertNull($result->challengeId);
        self::assertNull($result->expiresAt);
    }

    /**
     * A refusal waits at least a second, or not at all when waiting will not
     * help.
     *
     * @return void
     */
    public function testARefusalWaitsAtLeastASecondOrNotAtAll(): void
    {
        self::assertSame(1, SendResult::refused(FailureReason::SENDING_CAPPED, 0)->retryAfter);
        self::assertSame(1, SendResult::refused(FailureReason::SENDING_CAPPED, -3)->retryAfter);
        self::assertNull(SendResult::refused(FailureReason::NOT_FOUND)->retryAfter);
    }

    /**
     * A refusal by a challenge's admission carries its reason, and how long a
     * lockout has left when it ends at a set time.
     *
     * @return void
     */
    public function testARefusalByAnAdmission(): void
    {
        CarbonImmutable::setTestNow('2026-11-01 12:00:00');

        $locked = SendResult::refusedBy(ChallengeAdmission::locked(Lockout::endingAt(AttemptScope::FACTOR, CarbonImmutable::now()->addSeconds(90))));

        self::assertSame(FailureReason::LOCKED, $locked->reason);
        self::assertSame(90, $locked->retryAfter);

        $refused = SendResult::refusedBy(ChallengeAdmission::refuse(FailureReason::NOT_ACCEPTED, 'Not accepted.'));

        self::assertSame(FailureReason::NOT_ACCEPTED, $refused->reason);
        self::assertNull($refused->retryAfter);

        $ceiling = SendResult::refusedBy(ChallengeAdmission::locked(Lockout::disabled()));

        self::assertSame(FailureReason::LOCKED, $ceiling->reason);
        self::assertNull($ceiling->retryAfter);

        CarbonImmutable::setTestNow();
    }
}
