<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Unit tests for the `VerificationResult` value: a verified result carries the
 * proof and its evaluation, a failed one its reason and internal detail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationResult::class)]
final class VerificationResultTest extends TestCase
{
    use BuildsProofs;

    /**
     * A verified result carries the proof and its evaluation, and no reason.
     *
     * @return void
     */
    public function testAVerifiedResultCarriesTheProofAndItsEvaluation(): void
    {
        $proof      = self::proof();
        $evaluation = new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['otp', 'mfa'], [], []);

        $result = VerificationResult::verified($proof, $evaluation);

        self::assertTrue($result->isVerified());
        self::assertFalse($result->isFailed());
        self::assertSame($proof, $result->proof);
        self::assertSame($evaluation, $result->evaluation);
        self::assertNull($result->reason);
        self::assertNull($result->detail);
        self::assertNull($result->lockedUntil);
    }

    /**
     * A failed result carries its reason and internal detail, and no proof.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReasonAndDetail(): void
    {
        $result = VerificationResult::failed(FailureReason::NOT_FOUND, 'The factor belongs to another identity.');

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isVerified());
        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame('The factor belongs to another identity.', $result->detail);
        self::assertNull($result->proof);
        self::assertNull($result->evaluation);
        self::assertNull($result->lockedUntil);
    }

    /**
     * A lockout carries the time it lifts.
     *
     * @return void
     */
    public function testALockoutCarriesTheTimeItLifts(): void
    {
        $until = CarbonImmutable::parse('2026-11-01T10:15:00+00:00');

        $result = VerificationResult::failed(FailureReason::LOCKED, 'Five consecutive failures.', $until);

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame($until, $result->lockedUntil);
    }

    /**
     * Blank details.
     *
     * @return iterable<string, array{string}>
     */
    public static function provideBlankDetails(): iterable
    {
        yield 'empty' => [''];
        yield 'spaces' => ['  '];
    }

    /**
     * A failure always says why, internally.
     *
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('provideBlankDetails')]
    public function testABlankDetailIsRefused(string $detail): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The detail of a failed verification must not be blank.');

        VerificationResult::failed(FailureReason::INVALID_CODE, $detail);
    }

    /**
     * A lockout without the time it lifts is refused.
     *
     * @return void
     */
    public function testALockoutWithoutItsTimeIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A failure of reason [locked] carries the time the lockout lifts.');

        VerificationResult::failed(FailureReason::LOCKED, 'Locked.');
    }

    /**
     * Only a lockout carries a time.
     *
     * @return void
     */
    public function testATimeOnAnotherFailureIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only a failure of reason [locked] carries the time a lockout lifts, not [expired].');

        VerificationResult::failed(FailureReason::EXPIRED, 'The code expired.', CarbonImmutable::now());
    }
}
