<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeCheck::class)]
final class CodeCheckTest extends TestCase
{
    /**
     * @return void
     */
    public function testTheOutcomesArePinned(): void
    {
        self::assertSame(
            ['accepted', 'invalid', 'expired', 'exhausted', 'replayed', 'spent', 'missing'],
            array_map(static fn (CodeCheck $check): string => $check->value, CodeCheck::cases()),
        );
    }

    /**
     * Accepted is no failure, wrong is invalid, used is replayed, no live code
     * is expired, and absent or another's is not found.
     *
     * @return void
     */
    public function testEachOutcomeAnswersWithItsFailureReason(): void
    {
        self::assertNull(CodeCheck::ACCEPTED->failure());
        self::assertSame(FailureReason::INVALID_CODE, CodeCheck::INVALID->failure());
        self::assertSame(FailureReason::REPLAYED, CodeCheck::REPLAYED->failure());
        self::assertSame(FailureReason::EXPIRED, CodeCheck::EXPIRED->failure());
        self::assertSame(FailureReason::EXPIRED, CodeCheck::EXHAUSTED->failure());
        self::assertSame(FailureReason::EXPIRED, CodeCheck::SPENT->failure());
        self::assertSame(FailureReason::NOT_FOUND, CodeCheck::MISSING->failure());
    }

    /**
     * @return void
     */
    public function testEachOutcomeRecordsItsDetail(): void
    {
        self::assertSame([
            'accepted'  => 'The code matched and was used.',
            'invalid'   => 'The code did not match.',
            'expired'   => 'The code has expired.',
            'exhausted' => 'The challenge has used up its attempts.',
            'replayed'  => 'The code was already used.',
            'spent'     => 'The challenge was already used.',
            'missing'   => 'No code was sent for this factor, session, application and purpose.',
        ], array_combine(
            array_map(static fn (CodeCheck $check): string => $check->value, CodeCheck::cases()),
            array_map(static fn (CodeCheck $check): string => $check->detail(), CodeCheck::cases()),
        ));
    }
}
