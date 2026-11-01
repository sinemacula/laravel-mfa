<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * Finds which of a set's unused codes a submitted code is, with the same work
 * whichever matches and whether one does.
 *
 * The normalised code is checked with the hasher against every hash given: a
 * match never ends the loop, and the first is remembered only once its check
 * has returned, so a set of N codes always costs N checks. A malformed code
 * (`null`, see `RecoveryCodeNormalizer`) is checked the same way, against a
 * placeholder no stored code can be, and matches nothing. The work grows with
 * the number of unused codes, never with which one matched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecoveryCodeMatcher
{
    /** @var string What a malformed code is checked as: never a stored code, which is upper-case without hyphens. */
    public const string PLACEHOLDER = 'malformed-recovery-code';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key of the first hash the normalised code matches, or `null` when it
     * matches none or is malformed.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  array<int, string>  $hashes
     * @param  ?string  $normalized
     * @return ?int
     */
    public static function find(Hasher $hasher, array $hashes, #[\SensitiveParameter] ?string $normalized): ?int
    {
        $candidate = $normalized ?? self::PLACEHOLDER;
        $found     = null;

        foreach ($hashes as $key => $hash) {

            $matches = $hasher->check($candidate, $hash);

            if (!$matches || $found !== null) {
                continue;
            }

            $found = $key;
        }

        return $normalized === null ? null : $found;
    }
}
