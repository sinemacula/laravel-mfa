<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Schema\Builder;
use SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException;

/**
 * Fails a shipped migration before any schema change when its table already
 * exists, naming the setting that renames it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MigrationCollisionGuard
{
    /**
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** On the migration's connection. */
        private Builder $schema,
    ) {}

    /**
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
