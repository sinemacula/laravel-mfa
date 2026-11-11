<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * Finds which unused code a submitted code matches, always checking every hash
 * so the timing reveals neither which code matched nor whether one did.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecoveryCodeMatcher
{
    /** @var string Checked in place of a malformed code; no stored code is lower-case or hyphenated. */
    public const string PLACEHOLDER = 'malformed-recovery-code';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
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
