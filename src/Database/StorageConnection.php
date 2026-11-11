<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException;

/**
 * The one connection for every package table, since a factor state change
 * writes several tables in one transaction. The setting must not change during
 * a process's life: models take their connection when built.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StorageConnection
{
    /** @var string */
    private const string SETTING = 'mfa.storage.connection';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Null for the default connection.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function name(): ?string
    {
        $connection = Config::get(self::SETTING);

        if ($connection !== null && !is_string($connection)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be a connection name, or null or empty for the default connection.', self::SETTING));
        }

        return $connection === '' ? null : $connection;
    }

    /**
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function resolvedName(): string
    {
        return self::name() ?? Config::string('database.default');
    }

    /**
     * Named even when default, since Eloquent gives a related model that names
     * none its parent's connection. Null before configuration is bootstrapped.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function forModel(): ?string
    {
        return Config::getFacadeRoot() === null ? null : self::resolvedName();
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function nameOf(Model $model): string
    {
        return $model->getConnectionName() ?? Config::string('database.default');
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $setting
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException
     */
    public static function assertHolds(Model $model, string $setting): void
    {
        $own     = self::nameOf($model);
        $storage = self::resolvedName();

        if ($own === $storage) {
            return;
        }

        $message = '%s class [%s] must be on the storage connection (`%s`): the model is on [%s], the package\'s tables on [%s].';

        throw new ModelOffStorageConnectionException(sprintf($message, $setting, $model::class, self::SETTING, $own, $storage));
    }
}
