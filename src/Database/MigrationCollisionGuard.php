<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Schema\Builder;
use SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException;

/**
 * Migration collision guard.
 *
 * Helper for the shipped migrations. Surfaces a clear error before any schema
 * change if the table a migration is configured to create already exists.
 * Consumers who run a prior MFA system can avoid the collision by changing the
 * setting the message names before publishing the migrations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MigrationCollisionGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** Schema builder used to inspect the migration's connection for an existing table. */
        private Builder $schema,
    ) {}

    /**
     * Throw if the table already exists, naming the setting under `mfa` that
     * configures its name.
     *
     * @param  string  $table
     * @param  string  $setting
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException
     */
    public function ensureNotExists(string $table, string $setting): void
    {
        if (!$this->schema->hasTable($table)) {
            return;
        }

        $connection = $this->schema->getConnection()->getName() ?? 'default';

        $message = 'Cannot install the laravel-mfa migrations: a table named \'%s\' already exists on connection \'%s\'.'
            . ' Set `%s` in config/mfa.php to a different name and re-run the migration.';

        throw new TableAlreadyExistsException(sprintf($message, $table, $connection, $setting));
    }
}
