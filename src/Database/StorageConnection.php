<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Mfa\Exceptions\ModelOffStorageConnectionException;

/**
 * Where the package's tables live: the connection the shipped models read and
 * write, the one the shipped migrations create the tables on, and the one every
 * serialised change to an identity's factor state runs its transaction on, so
 * the three cannot disagree.
 *
 * Every table lives on `mfa.storage.connection` (`null` or empty for the
 * default connection). They are kept together because a change that depends on
 * the identity's whole factor state (confirming a factor, replacing the
 * recovery codes, removing a factor, a reset) writes several of them in one
 * transaction, which two connections cannot commit as one; a model on another
 * connection is refused rather than splitting one.
 *
 * A model takes its connection when it is built, so the setting must stay the
 * same for the life of a process: moving the tables is a deploy, with a worker
 * restart and a migration the application performs, not a runtime switch.
 * Connections are compared by name, a model's own or the default one, so no
 * connection is opened.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class StorageConnection
{
    /** @var string The setting that names the connection. */
    private const string SETTING = 'mfa.storage.connection';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The connection the package's tables live on, or `null` for the default
     * connection.
     *
     * A value that is neither a name nor `null` or empty fails closed rather
     * than putting a table on another connection than the one meant.
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
     * The name of the storage connection: the configured one, or the default
     * one.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function resolvedName(): string
    {
        return self::name() ?? Config::string('database.default');
    }

    /**
     * The connection a shipped model is built on: the storage connection by
     * name, the default one included, since Eloquent gives a related model that
     * names none its parent's connection; `null` (the default connection) while
     * the configuration is not yet bootstrapped.
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
     * The name of the model's connection: its own, or the default one.
     *
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
     * Refuse a model that does not live on the storage connection, naming the
     * setting that configures it and both connections.
     *
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
