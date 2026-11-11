<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Drivers\Base32;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Base32::class)]
final class Base32Test extends TestCase
{
    /**
     * The RFC 4648 section 10 vectors without padding, and bytes at both ends
     * of the range.
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
     * @return void
     */
    public function testDecodesLowerCaseAndPaddedText(): void
    {
        self::assertSame('foobar', Base32::decode('mzxw6ytboi'));
        self::assertSame('foobar', Base32::decode('MZXW6YTBOI======'));
        self::assertSame('f', Base32::decode('my======'));
    }

    /**
     * @return void
     */
    public function testDropsBitsLeftOverAfterTheLastWholeByte(): void
    {
        self::assertSame('f', Base32::decode('MZX'));
    }

    /**
     * @return void
     */
    public function testRefusesTextOutsideTheAlphabet(): void
    {
        foreach (['MZXW6YTBO1', 'MZXW 6YTB', 'MZ=XW6', 'MZXW6YTBOI8', '-'] as $text) {
            self::assertNull(Base32::decode($text), $text);
        }
    }

    /**
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
