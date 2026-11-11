<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

/**
 * Strips ASCII whitespace and hyphens and upper-cases ASCII letters; Unicode
 * dashes and spaces are kept, so a code containing one never matches.
 *
 * The configured length and alphabet are not checked, so a set issued before
 * either changed still redeems.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecoveryCodeNormalizer
{
    /** @var int Longest submitted code that is normalised, in bytes. */
    public const int MAXIMUM_INPUT_BYTES = 256;

    /** @var list<string> ASCII whitespace and the hyphen. */
    private const array REMOVED = [' ', "\t", "\r", "\n", "\v", "\f", '-'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Null when the input is too long to be a code.
     *
     * @param  string  $input
     * @return ?string
     */
    public static function normalize(#[\SensitiveParameter] string $input): ?string
    {
        if (strlen($input) > self::MAXIMUM_INPUT_BYTES) {
            return null;
        }

        $normalized = strtoupper(str_replace(self::REMOVED, '', $input));

        return strlen($normalized) > RecoveryCodeSettings::MAXIMUM_LENGTH ? null : $normalized;
    }
}
