<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeMatcher;
use Tests\Fixtures\RecoveryCodes\CountingHasher;

/**
 * Unit tests for `RecoveryCodeMatcher`: the work does not depend on which code
 * matches, or whether one does. The submitted code is checked against every
 * hash, in order, whether the match is first, in the middle, last or absent,
 * and a malformed code is checked as the placeholder against every hash too,
 * and matches nothing.
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
     * Where the submitted code sits in the set, if anywhere, and the key it
     * matches.
     *
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
     * Whichever code matches, and when none does, every hash is checked, with
     * the submitted code, and the key of the match is returned.
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
     * A malformed code is checked as the placeholder against every hash, and
     * matches nothing, even a hash of the placeholder itself.
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
     * Of two hashes the code matches, the first is the match.
     *
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
     * An empty set checks nothing and matches nothing.
     *
     * @return void
     */
    public function testAnEmptySetChecksNothing(): void
    {
        $hasher = new CountingHasher;

        self::assertNull(RecoveryCodeMatcher::find($hasher, [], 'AAAAAAAAAAAA'));
        self::assertSame(0, $hasher->checks());
    }

    /**
     * The hashes of the set's codes.
     *
     * @param  \Tests\Fixtures\RecoveryCodes\CountingHasher  $hasher
     * @return list<string>
     */
    private static function hashes(CountingHasher $hasher): array
    {
        return array_map(static fn (string $code): string => $hasher->make($code), self::CODES);
    }
}
