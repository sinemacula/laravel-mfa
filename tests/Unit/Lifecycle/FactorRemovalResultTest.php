<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use Tests\Fixtures\Verification\Dumps;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRemovalResult::class)]
final class FactorRemovalResultTest extends TestCase
{
    /**
     * @return void
     */
    public function testCarriesTheCompletionOfARemovalMade(): void
    {
        $completion = self::completion();
        $made       = FactorRemovalResult::made(self::factor(), null, $completion);

        self::assertTrue($made->wasMade());
        self::assertSame($completion, $made->completion());
        self::assertNull(FactorRemovalResult::made(self::factor(), null)->completion());
        self::assertNull(FactorRemovalResult::refused(FailureReason::NOT_FOUND)->completion());
    }

    /**
     * @return void
     */
    public function testNoDumpShowsTheCompletion(): void
    {
        foreach (Dumps::of(FactorRemovalResult::made(self::factor(), null, self::completion())) as $way => $shown) {
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
     * @return \SineMacula\Laravel\Mfa\Factors\FactorSummary
     */
    private static function factor(): FactorSummary
    {
        return new FactorSummary('factor-totp', 'totp', null, null, FactorStatus::CONFIRMED, false, null);
    }
}
