<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\Base32;

/**
 * Unit tests for `Base32`: the RFC 4648 test vectors both ways, the forms of a
 * secret decoding accepts, and the text it refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Base32::class)]
final class Base32Test extends TestCase
{
    /**
     * Rows of `[bytes, encoded]`: the RFC 4648 §10 vectors without their
     * padding, and bytes at both ends of the range.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function vectors(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'f' => ['f', 'MY'];
        yield 'fo' => ['fo', 'MZXQ'];
        yield 'foo' => ['foo', 'MZXW6'];
        yield 'foob' => ['foob', 'MZXW6YQ'];
        yield 'fooba' => ['fooba', 'MZXW6YTB'];
        yield 'foobar' => ['foobar', 'MZXW6YTBOI'];
        yield 'edge bytes' => ["\x00\xFF\x10", 'AD7RA'];
        yield 'rfc 6238 key' => ['12345678901234567890', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'];
    }

    /**
     * Encoding gives the vector, upper case and unpadded.
     *
     * @param  string  $bytes
     * @param  string  $encoded
     * @return void
     */
    #[DataProvider('vectors')]
    public function testEncodesTheVector(string $bytes, string $encoded): void
    {
        self::assertSame($encoded, Base32::encode($bytes));
    }

    /**
     * Decoding the vector gives back its bytes.
     *
     * @param  string  $bytes
     * @param  string  $encoded
     * @return void
     */
    #[DataProvider('vectors')]
    public function testDecodesTheVector(string $bytes, string $encoded): void
    {
        self::assertSame($bytes, Base32::decode($encoded));
    }

    /**
     * Lower case and trailing padding decode as the canonical form does.
     *
     * @return void
     */
    public function testDecodesLowerCaseAndPaddedText(): void
    {
        self::assertSame('foobar', Base32::decode('mzxw6ytboi'));
        self::assertSame('foobar', Base32::decode('MZXW6YTBOI======'));
        self::assertSame('f', Base32::decode('my======'));
    }

    /**
     * Bits left over after the last whole byte are dropped, even when they are
     * one short of another byte.
     *
     * @return void
     */
    public function testDropsBitsLeftOverAfterTheLastWholeByte(): void
    {
        self::assertSame('f', Base32::decode('MZX'));
    }

    /**
     * Text holding a character outside the alphabet, padding before the end
     * included, decodes to nothing.
     *
     * @return void
     */
    public function testRefusesTextOutsideTheAlphabet(): void
    {
        foreach (['MZXW6YTBO1', 'MZXW 6YTB', 'MZ=XW6', 'MZXW6YTBOI8', '-'] as $text) {
            self::assertNull(Base32::decode($text), $text);
        }
    }

    /**
     * Random bytes survive a round trip, whatever their length.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRoundTripsRandomBytes(): void
    {
        foreach ([1, 2, 3, 4, 5, 20, 32, 64] as $length) {
            $bytes = random_bytes($length);

            self::assertSame($bytes, Base32::decode(Base32::encode($bytes)));
        }
    }
}
