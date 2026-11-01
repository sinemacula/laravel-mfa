<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;

/**
 * Unit tests for `CodeCheck`: the outcomes, the failure reason each answers
 * with, and the internal detail each records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeCheck::class)]
final class CodeCheckTest extends TestCase
{
    /**
     * The outcomes are pinned, so a rename fails.
     *
     * @return void
     */
    public function testTheOutcomesArePinned(): void
    {
        self::assertSame(
            ['accepted', 'invalid', 'expired', 'exhausted', 'replayed', 'missing'],
            array_map(static fn (CodeCheck $check): string => $check->value, CodeCheck::cases()),
        );
    }

    /**
     * An accepted code is no failure; a wrong one is an invalid code, a used
     * one replayed, and a check with no live code to compare is expired.
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
        self::assertSame(FailureReason::EXPIRED, CodeCheck::MISSING->failure());
    }

    /**
     * Each outcome records a detail of its own.
     *
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
            'missing'   => 'No code was sent for this factor, session, application and purpose.',
        ], array_combine(
            array_map(static fn (CodeCheck $check): string => $check->value, CodeCheck::cases()),
            array_map(static fn (CodeCheck $check): string => $check->detail(), CodeCheck::cases()),
        ));
    }
}
