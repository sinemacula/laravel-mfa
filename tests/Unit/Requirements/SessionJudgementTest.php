<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionJudgement;
use Tests\Fixtures\Verification\Dumps;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionJudgement::class)]
final class SessionJudgementTest extends TestCase
{
    /**
     * @return void
     */
    public function testCarriesTheAssessmentAndTheCompletion(): void
    {
        $outstanding = Requirement::none()->withAdditionalVerification();
        $completion  = self::completion();
        $judgement   = new SessionJudgement($outstanding, $completion);

        self::assertSame($outstanding, $judgement->outstanding);
        self::assertSame($completion, $judgement->completion());
        self::assertNull((new SessionJudgement(null))->completion());
    }

    /**
     * @return void
     */
    public function testNoDumpShowsTheCompletion(): void
    {
        foreach (Dumps::of(new SessionJudgement(null, self::completion())) as $way => $shown) {
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
}
