<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

/**
 * Base32 (RFC 4648 section 6), unpadded upper case as `otpauth://` URIs expect.
 * Decoding also accepts lower case and `=` padding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Base32
{
    /** @var string The 32 characters, in value order. */
    public const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  string  $bytes
     * @return string
     */
    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        $bits = '';

        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $encoded = '';

        foreach (str_split($bits, 5) as $group) {
            $encoded .= self::ALPHABET[(int) bindec(str_pad($group, 5, '0'))];
        }

        return $encoded;
    }

    /**
     * Null for a character outside the alphabet. Bits after the last whole byte
     * are dropped, as RFC 4648 does.
     *
     * @param  string  $encoded
     * @return ?string
     */
    public static function decode(#[\SensitiveParameter] string $encoded): ?string
    {
        $bits = '';

        foreach (str_split(strtoupper(rtrim($encoded, '='))) as $character) {

            $value = strpos(self::ALPHABET, $character);

            if ($value === false) {
                return null;
            }

            $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';

        for ($offset = 0; $offset + 8 <= strlen($bits); $offset += 8) {
            $bytes .= chr((int) bindec(substr($bits, $offset, 8)));
        }

        return $bytes;
    }
}
