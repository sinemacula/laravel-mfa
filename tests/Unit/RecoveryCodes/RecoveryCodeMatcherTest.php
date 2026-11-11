<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeMatcher;
use Tests\Fixtures\RecoveryCodes\CountingHasher;

/**
 * The work must not depend on which code matches, or whether one does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeMatcher::class)]
final class RecoveryCodeMatcherTest extends TestCase
{
    /** @var list<string> The codes of the set, in the order their hashes are checked. */
    private const array CODES = ['AAAAAAAAAAAA', 'BBBBBBBBBBBB', 'CCCCCCCCCCCC', 'DDDDDDDDDDDD', 'EEEEEEEEEEEE'];

    /**
     * @return iterable<string, array{string, ?int}>
     */
    public static function positions(): iterable
    {
        yield 'first' => ['AAAAAAAAAAAA', 0];
        yield 'middle' => ['CCCCCCCCCCCC', 2];
        yield 'last' => ['EEEEEEEEEEEE', 4];
        yield 'absent' => ['ZZZZZZZZZZZZ', null];
    }

    /**
     * The key of the match is returned.
     *
     * @param  string  $submitted
     * @param  ?int  $key
     * @return void
     */
    #[DataProvider('positions')]
    public function testEveryHashIsCheckedWhicheverMatches(string $submitted, ?int $key): void
    {
        $hasher = new CountingHasher;

        self::assertSame($key, RecoveryCodeMatcher::find($hasher, self::hashes($hasher), $submitted));
        self::assertSame(array_fill(0, 5, $submitted), $hasher->checked);
    }

    /**
     * Checked as the placeholder; not even the placeholder's own hash matches.
     *
     * @return void
     */
    public function testAMalformedCodeIsCheckedAgainstEveryHashAndMatchesNothing(): void
    {
        $hasher = new CountingHasher;
        $hashes = [...self::hashes($hasher), $hasher->make(RecoveryCodeMatcher::PLACEHOLDER)];

        self::assertNull(RecoveryCodeMatcher::find($hasher, $hashes, null));
        self::assertSame(array_fill(0, 6, RecoveryCodeMatcher::PLACEHOLDER), $hasher->checked);
    }

    /**
     * @return void
     */
    public function testTheFirstMatchIsKept(): void
    {
        $hasher = new CountingHasher;
        $hashes = [7 => $hasher->make('OTHER'), 8 => $hasher->make('TWICE'), 9 => $hasher->make('TWICE')];

        self::assertSame(8, RecoveryCodeMatcher::find($hasher, $hashes, 'TWICE'));
        self::assertSame(3, $hasher->checks());
    }

    /**
     * @return void
     */
    public function testAnEmptySetChecksNothing(): void
    {
        $hasher = new CountingHasher;

        self::assertNull(RecoveryCodeMatcher::find($hasher, [], 'AAAAAAAAAAAA'));
        self::assertSame(0, $hasher->checks());
    }

    /**
     * @param  \Tests\Fixtures\RecoveryCodes\CountingHasher  $hasher
     * @return list<string>
     */
    private static function hashes(CountingHasher $hasher): array
    {
        return array_map(static fn (string $code): string => $hasher->make($code), self::CODES);
    }
}
