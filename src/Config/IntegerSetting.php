<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Reads an integer package setting.
 *
 * Two fallback values are accepted so callers can distinguish "absent" (key
 * missing: use a sensible default) from "malformed" (key present but not
 * numeric: fail safe by using `$malformedFallback`, typically 0). The asymmetry
 * is deliberate: a misconfigured expiry value should not silently grant a long
 * valid window.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerSetting
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The setting under the key as an integer: the default when the key is not
     * set, and the malformed fallback (or the default, when none is given) when
     * the value is not numeric.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  int  $default
     * @param  ?int  $malformedFallback
     * @return int
     */
    public static function read(Repository $config, string $key, int $default, ?int $malformedFallback = null): int
    {
        if (!$config->has($key)) {
            return $default;
        }

        /** @var mixed $value */
        $value = $config->get($key);

        // `is_numeric` is true for ints AND numeric-strings; the subsequent
        // `(int)` cast is identity for ints, so a single arm covers both shapes
        // without a redundant `is_int` branch.
        return is_numeric($value)
            ? (int) $value
            : ($malformedFallback ?? $default);
    }
}
