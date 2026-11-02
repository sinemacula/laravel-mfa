<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Whether a factor is confirmed as a fact: its stored status is exactly
 * `confirmed`, compared in PHP, never in SQL, where a collation may ignore case
 * or padding. A status that is anything else, one none the package knows
 * included, is no confirmed factor, and nothing here throws on it.
 *
 * This is the fact a recovery code is admitted on and the authentication
 * context reports. Whether an identity is held to MFA is a different and
 * conservative question, answered by `isMfaEnabled()`, which counts every
 * factor that is not pending.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfirmedFactors
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Determine whether the factor's stored status is exactly `confirmed`.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     */
    public static function isConfirmed(EloquentFactor&Model $factor): bool
    {
        return ($factor->getAttributes()[$factor->getStatusName()] ?? null) === FactorStatus::CONFIRMED->value;
    }

    /**
     * Determine whether any of the factors is confirmed.
     *
     * @param  iterable<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return bool
     */
    public static function isAmong(iterable $factors): bool
    {
        foreach ($factors as $factor) {

            if (self::isConfirmed($factor)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the identity holds a confirmed factor of the configured
     * model, read from the write connection and matched to the identity exactly
     * (see `FactorStateTransaction::snapshot()`).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public static function isHeldBy(MultiFactorAuthenticatable $identity, Repository $config): bool
    {
        $model = ConfiguredModels::factor($config);

        return self::isAmong(FactorStateTransaction::snapshot($identity, new $model));
    }
}
