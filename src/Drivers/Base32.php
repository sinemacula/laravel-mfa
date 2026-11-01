<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

/**
 * Base32 (RFC 4648 §6) as authenticator apps exchange TOTP secrets: the
 * alphabet `A` to `Z` and `2` to `7`, written upper case and without padding,
 * which is what the `otpauth://` key URI format expects.
 *
 * Decoding accepts lower case and trailing `=` padding, so a secret written
 * either way reads the same, and refuses anything else, returning `null`
 * rather than guessing at what was meant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Base32
{
    /** @var string The 32 characters, in the order of the values they stand for. */
    public const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Encode the bytes, upper case and without padding.
     *
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
     * Decode the text, or return `null` when it holds a character outside the
     * alphabet. Bits left over after the last whole byte are dropped, as RFC
     * 4648 does.
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
