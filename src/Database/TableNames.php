<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Support\Facades\Config;

/**
 * The name of every table the package creates, each configurable in its
 * capability's block (`mfa.{block}.table`) and defaulting to a name prefixed
 * `mfa_`, read in one place so the migrations, the models and the queries that
 * write a table by name always agree.
 *
 * A blank or missing setting takes the default, as does any read before the
 * configuration is bootstrapped (a model built that early); the configuration
 * check refuses a setting that is not a name, and two tables sharing one.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableNames
{
    /** @var string The factors, one row per enrolled or pending factor. */
    public const string FACTORS = 'factor';

    /** @var string One row per identity: its factor state lock, generation, obligation and failures. */
    public const string IDENTITY_STATES = 'identity_state';

    /** @var string One row per enrolment in progress: its grant and bindings. */
    public const string ENROLLMENTS = 'enrollment';

    /** @var string The delivered codes, hashed and bound to their factor and session. */
    public const string CODES = 'codes';

    /** @var string The recovery codes, hashed, one set per identity. */
    public const string RECOVERY_CODES = 'recovery_codes';

    /** @var string The temporary attempt throttles, one row per scope, subject and window. */
    public const string ATTEMPTS = 'attempts';

    /** @var string The associations of passkeys with factors. */
    public const string PASSKEY_ASSOCIATIONS = 'passkeys';

    /** @var array<string, string> Each table's block and its default name. */
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
     * The configured name of the table of the given block, or its default.
     *
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
     * The setting that names the table of the given block.
     *
     * @param  string  $block
     * @return string
     */
    public static function setting(string $block): string
    {
        return 'mfa.' . $block . '.table';
    }
}
