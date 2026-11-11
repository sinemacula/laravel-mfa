<?php

declare(strict_types = 1);

namespace Tests\Unit\Enrollment;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use Tests\Fixtures\Verification\Dumps;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentConfirmation::class)]
final class EnrollmentConfirmationTest extends TestCase
{
    /**
     * A failure carries no completion.
     *
     * @return void
     */
    public function testCarriesTheCompletionOfAConfirmation(): void
    {
        $completion   = self::completion();
        $confirmation = EnrollmentConfirmation::confirmed(self::factor(), completion: $completion);

        self::assertTrue($confirmation->isConfirmed());
        self::assertSame($completion, $confirmation->completion());
        self::assertNull(EnrollmentConfirmation::confirmed(self::factor())->completion());
        self::assertNull(EnrollmentConfirmation::failed(FailureReason::NOT_FOUND)->completion());
    }

    /**
     * @return void
     */
    public function testNoDumpShowsTheCompletion(): void
    {
        foreach (Dumps::of(EnrollmentConfirmation::confirmed(self::factor(), completion: self::completion())) as $way => $shown) {
            self::assertStringNotContainsString('bearer-token', $shown, $way);
        }
    }

    /**
     * @return object
     */
    private static function completion(): object
    {
        return (object) ['token' => 'bearer-token'];
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(): FactorSummary
    {
        return new FactorSummary('factor-totp', 'totp', null, null, FactorStatus::CONFIRMED, false, null);
    }
}
