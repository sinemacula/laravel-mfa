<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode as RecoveryCodeModel;

/**
 * The model classes an application may replace through configuration. An
 * invalid class throws rather than falling back, so a typo cannot go unnoticed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfiguredModels
{
    /** @var string */
    public const string FACTOR = 'mfa.factor.model';

    /** @var string */
    public const string RECOVERY_CODE = 'mfa.recovery_codes.model';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public static function factor(Repository $config): string
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> */
        return self::resolve($config, self::FACTOR, Factor::class, EloquentFactor::class);
    }

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public static function recoveryCode(Repository $config): string
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode> */
        return self::resolve($config, self::RECOVERY_CODE, RecoveryCodeModel::class, RecoveryCode::class);
    }

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $setting
     * @param  class-string  $shipped
     * @param  class-string  $contract
     * @return class-string
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private static function resolve(Repository $config, string $setting, string $shipped, string $contract): string
    {
        /** @var mixed $configured */
        $configured = $config->get($setting);

        if ($configured === null) {
            return $shipped;
        }

        if (!is_string($configured) || $configured === '') {
            throw new InvalidModelException(sprintf('%s must be a class string; got [%s].', $setting, get_debug_type($configured)));
        }

        if (!class_exists($configured)) {
            throw new InvalidModelException(sprintf('%s class [%s] does not exist.', $setting, $configured));
        }

        if (!is_subclass_of($configured, $contract) || !is_subclass_of($configured, Model::class)) {
            throw new InvalidModelException(sprintf('%s class [%s] must extend %s and implement %s.', $setting, $configured, Model::class, $contract));
        }

        return $configured;
    }
}
