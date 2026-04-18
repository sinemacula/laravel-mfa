<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\Schema\Builder;
use SineMacula\Laravel\Mfa\Exceptions\FactorTableAlreadyExistsException;

/**
 * Migration collision guard.
 *
 * Helper for the shipped factors migration. Surfaces a clear error before any
 * schema mutation if the configured factors table already exists. Consumers who
 * run a prior MFA system can avoid the collision by rebinding
 * `mfa.factor.table` before publishing the migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class MigrationCollisionGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** Schema builder used to inspect the configured connection for an existing factors table. */
        private Builder $schema,

    ) {}

    /**
     * Throw if the configured factors table already exists.
     *
     * @param  string  $table
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorTableAlreadyExistsException
     */
    public function ensureNotExists(string $table): void
    {
        if (!$this->schema->hasTable($table)) {
            return;
        }

        $connection = $this->schema->getConnection()->getName() ?? 'default';

        $message = sprintf(
            '%s %s %s',
            sprintf(
                'Cannot install the laravel-mfa factors migration: a table '
                . 'named \'%s\' already exists on connection \'%s\'.',
                $table,
                $connection,
            ),
            'Set `factor.table` in config/mfa.php to a different name',
            'and re-run the migration.',
        );

        throw new FactorTableAlreadyExistsException($message);
    }
}
