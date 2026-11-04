<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult;
use Tests\Fixtures\Verification\Dumps;

/**
 * Unit tests for `PasskeyAssociationResult`: an association on an active
 * session carries what the transition returned, hidden from every dump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyAssociationResult::class)]
final class PasskeyAssociationResultTest extends TestCase
{
    /**
     * The result returns its completion as given, and none by default.
     *
     * @return void
     */
    public function testCarriesTheCompletion(): void
    {
        $completion = self::completion();

        self::assertSame($completion, (new PasskeyAssociationResult(self::factor(), completion: $completion))->completion());
        self::assertNull((new PasskeyAssociationResult(self::factor()))->completion());
    }

    /**
     * No way of dumping it shows the completion.
     *
     * @return void
     */
    public function testNoDumpShowsTheCompletion(): void
    {
        foreach (Dumps::of(new PasskeyAssociationResult(self::factor(), completion: self::completion())) as $way => $shown) {
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
