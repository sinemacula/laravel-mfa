<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeNormalizer;

/**
 * Unit tests for `RecoveryCodeNormalizer`: ASCII case folded, ASCII whitespace
 * and hyphens removed, nothing else mapped, no check of the configured length
 * or alphabet, and input too long to be a code malformed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeNormalizer::class)]
final class RecoveryCodeNormalizerTest extends TestCase
{
    /**
     * Inputs and what they normalise to.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function inputs(): iterable
    {
        yield 'already normal' => ['ABCDEFGHJKLM', 'ABCDEFGHJKLM'];
        yield 'lower case' => ['abcdefghjklm', 'ABCDEFGHJKLM'];
        yield 'grouped with hyphens' => ['abcd-efgh-jklm', 'ABCDEFGHJKLM'];
        yield 'grouped with spaces' => [' abcd efgh jklm ', 'ABCDEFGHJKLM'];
        yield 'tabs, line breaks, vertical tabs and form feeds' => ["ab\tcd\r\nef\vgh\fjk\nlm", 'ABCDEFGHJKLM'];
        yield 'a Unicode dash is left in' => ["abcd\u{2013}efgh", "ABCD\u{2013}EFGH"];
        yield 'a non-breaking space is left in' => ["abcd\u{00A0}efgh", "ABCD\u{00A0}EFGH"];
        yield 'a non-ASCII letter is not case folded' => ["\u{00E9}abc", "\u{00E9}ABC"];
        yield 'a code of another length' => ['abc', 'ABC'];
        yield 'characters outside the alphabet' => ['0o1i', '0O1I'];
        yield 'nothing' => ['', ''];
    }

    /**
     * Each input normalises as expected.
     *
     * @param  string  $input
     * @param  string  $normalized
     * @return void
     */
    #[DataProvider('inputs')]
    public function testNormalizesTheInput(string $input, string $normalized): void
    {
        self::assertSame($normalized, RecoveryCodeNormalizer::normalize($input));
    }

    /**
     * Input of up to 256 bytes is normalised, whatever it reduces to; longer
     * input is malformed, even when it would reduce to a code.
     *
     * @return void
     */
    public function testInputLongerThan256BytesIsMalformed(): void
    {
        $padded = str_repeat('-', 244) . 'ABCDEFGHJKLM';

        self::assertSame(256, strlen($padded));
        self::assertSame('ABCDEFGHJKLM', RecoveryCodeNormalizer::normalize($padded));
        self::assertNull(RecoveryCodeNormalizer::normalize('-' . $padded));
    }

    /**
     * A normalised code of up to 64 characters, the longest a code can be, is
     * kept; a longer one is malformed.
     *
     * @return void
     */
    public function testANormalizedCodeLongerThan64CharactersIsMalformed(): void
    {
        self::assertSame(str_repeat('A', 64), RecoveryCodeNormalizer::normalize(str_repeat('a', 64)));
        self::assertNull(RecoveryCodeNormalizer::normalize(str_repeat('a', 65)));
        self::assertSame(str_repeat('A', 64), RecoveryCodeNormalizer::normalize(implode('-', str_split(str_repeat('a', 64), 4))));
    }
}
