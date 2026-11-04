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
 * Unit tests for `EnrollmentConfirmation`: a confirmation on an active session
 * carries what the transition returned, hidden from every dump; a failure
 * carries none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnrollmentConfirmation::class)]
final class EnrollmentConfirmationTest extends TestCase
{
    /**
     * A confirmation returns its completion as given; a failure has none.
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
     * No way of dumping it shows the completion.
     *
     * @return void
     */
    public function testNoDumpShowsTheCompletion(): void
    {
        foreach (Dumps::of(EnrollmentConfirmation::confirmed(self::factor(), completion: self::completion())) as $way => $shown) {
            self::assertStringNotContainsString('bearer-token', $shown, $way);
        }
    }

    /**
     * A completion holding a credential.
     *
     * @return object
     */
    private static function completion(): object
    {
        return (object) ['token' => 'bearer-token'];
    }

    /**
     * A confirmed TOTP factor.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(): FactorSummary
    {
        return new FactorSummary('factor-totp', 'totp', null, null, FactorStatus::CONFIRMED, false, null);
    }
}
