<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

/**
 * Puts a submitted recovery code in the form its hash was made from: ASCII
 * whitespace (space, tab, carriage return, line feed, vertical tab and form
 * feed) and hyphens removed, ASCII letters upper-cased. Nothing else is
 * mapped: a Unicode dash or space is left in, so a code containing one never
 * matches.
 *
 * The result is not checked against the configured length or alphabet, so a
 * set issued before either changed still redeems. Input too long to be a code
 * is malformed: more than `MAXIMUM_INPUT_BYTES` as submitted, or more than
 * `RecoveryCodeSettings::MAXIMUM_LENGTH` once normalised, the longest a code
 * can be. A malformed code is `null`, and the redemption still checks the whole
 * set, against a placeholder, so it is never rejected sooner than a code that
 * does not match.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecoveryCodeNormalizer
{
    /** @var int The longest submitted code that is normalised, in bytes. */
    public const int MAXIMUM_INPUT_BYTES = 256;

    /** @var list<string> What normalisation removes: ASCII whitespace and the hyphen. */
    private const array REMOVED = [' ', "\t", "\r", "\n", "\v", "\f", '-'];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The normalised form of the submitted code, or `null` when it is
     * malformed.
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
