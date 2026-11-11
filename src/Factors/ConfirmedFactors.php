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
 * Whether a stored status is exactly `confirmed`, compared in PHP since a SQL
 * collation may ignore case or padding. An unknown status is not confirmed.
 *
 * `isMfaEnabled()` answers the more conservative question of being held to MFA.
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
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     */
    public static function isConfirmed(EloquentFactor&Model $factor): bool
    {
        return ($factor->getAttributes()[$factor->getStatusName()] ?? null) === FactorStatus::CONFIRMED->value;
    }

    /**
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
