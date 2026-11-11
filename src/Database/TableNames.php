<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Support\Facades\Config;

/**
 * Every table name, read in one place so migrations, models and queries agree.
 * A blank setting, or a read before configuration is bootstrapped, takes the
 * default.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableNames
{
    /** @var string One row per enrolled or pending factor. */
    public const string FACTORS = 'factor';

    /** @var string One row per identity: its factor state lock, generation, obligation and failures. */
    public const string IDENTITY_STATES = 'identity_state';

    /** @var string One row per enrolment in progress: its grant and bindings. */
    public const string ENROLLMENTS = 'enrollment';

    /** @var string Delivered codes, hashed. */
    public const string CODES = 'codes';

    /** @var string Recovery codes, hashed, one set per identity. */
    public const string RECOVERY_CODES = 'recovery_codes';

    /** @var string Attempt throttles, one row per scope, subject and window. */
    public const string ATTEMPTS = 'attempts';

    /** @var string Passkey associations with factors. */
    public const string PASSKEY_ASSOCIATIONS = 'passkeys';

    /** @var array<string, string> Block => default name. */
    public const array DEFAULTS = [
        self::FACTORS              => 'mfa_factors',
        self::IDENTITY_STATES      => 'mfa_identity_states',
        self::ENROLLMENTS          => 'mfa_enrollments',
        self::CODES                => 'mfa_codes',
        self::RECOVERY_CODES       => 'mfa_recovery_codes',
        self::ATTEMPTS             => 'mfa_attempts',
        self::PASSKEY_ASSOCIATIONS => 'mfa_passkey_associations',
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  string  $block
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function of(string $block): string
    {
        $default = self::DEFAULTS[$block] ?? throw new \InvalidArgumentException(sprintf('The package creates no table for [%s].', $block));

        if (Config::getFacadeRoot() === null) {
            return $default;
        }

        $table = Config::get(self::setting($block));

        return is_string($table) && trim($table) !== '' ? $table : $default;
    }

    /**
     * @param  string  $block
     * @return string
     */
    public static function setting(string $block): string
    {
        return 'mfa.' . $block . '.table';
    }
}
