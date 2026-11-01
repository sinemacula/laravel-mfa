<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Engine-agnostic migration smoke test.
 *
 * Asserts that the shipped `mfa_factors` and `mfa_identity_states` tables exist
 * with every expected column and index after the package migrations run
 * end-to-end. Catches engine-specific schema bugs that would otherwise ship
 * behind a green badge — e.g. a column type MySQL accepts but PostgreSQL
 * rejects, or an index name that collides with a reserved identifier on one
 * engine.
 *
 * The "database-tests" CI matrix runs this against MySQL and PostgreSQL (with
 * `DB_CONNECTION` exported); local runs hit in-memory SQLite by default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class MigrationSmokeTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Every column the manager + drivers read or write must exist on the
     * freshly migrated `mfa_factors` table — this is the schema contract the
     * rest of the test suite implicitly assumes.
     *
     * @return void
     */
    public function testFactorsTableHasEveryRequiredColumn(): void
    {
        self::assertTrue(Schema::hasTable('mfa_factors'));

        $expected = [
            'id',
            'authenticatable_type',
            'authenticatable_id',
            'driver',
            'label',
            'recipient',
            'secret',
            'code',
            'expires_at',
            'attempts',
            'locked_until',
            'last_attempted_at',
            'verified_at',
            'created_at',
            'updated_at',
        ];

        foreach ($expected as $column) {
            self::assertTrue(
                Schema::hasColumn('mfa_factors', $column),
                sprintf('Missing column [%s] on mfa_factors after migration.', $column),
            );
        }
    }

    /**
     * The polymorphic lookup path (`Mfa::getFactors()` and the manager cache)
     * reads `WHERE authenticatable_type = ? AND authenticatable_id = ?` on
     * every request. The index that backs that query must exist, regardless of
     * engine.
     *
     * @return void
     */
    public function testFactorsTableHasPolymorphicLookupIndex(): void
    {
        $columns = Schema::getIndexes('mfa_factors');

        $hasMorphIndex = false;

        foreach ($columns as $index) {
            $cols = $index['columns'];

            if (in_array('authenticatable_type', $cols, true) && in_array('authenticatable_id', $cols, true)) {
                $hasMorphIndex = true;

                break;
            }
        }

        self::assertTrue(
            $hasMorphIndex,
            'Expected a composite index on (authenticatable_type, authenticatable_id) for polymorphic lookup.',
        );
    }

    /**
     * The identity states table holds one row per owner: the unique index the
     * factor state lock inserts or updates against must exist on every engine.
     *
     * @return void
     */
    public function testIdentityStatesTableHasOneRowPerOwner(): void
    {
        self::assertTrue(Schema::hasTable('mfa_identity_states'));

        foreach (['id', 'authenticatable_type', 'authenticatable_id', 'created_at', 'updated_at'] as $column) {
            self::assertTrue(
                Schema::hasColumn('mfa_identity_states', $column),
                sprintf('Missing column [%s] on mfa_identity_states after migration.', $column),
            );
        }

        $unique = array_filter(
            Schema::getIndexes('mfa_identity_states'),
            static fn (array $index): bool => $index['unique'] && $index['columns'] === ['authenticatable_type', 'authenticatable_id'],
        );

        self::assertCount(1, $unique, 'Expected one unique index on (authenticatable_type, authenticatable_id).');
        self::assertSame('mfa_identity_states_owner_unique', array_values($unique)[0]['name']);
    }

    /**
     * A long configured identity states table name still gives an owner index
     * name every engine accepts: cut short and hashed, the same on every run.
     *
     * @return void
     */
    public function testALongIdentityStatesTableNameGivesAShortOwnerIndexName(): void
    {
        $table = str_pad('mfa_identity_states_', 60, 'x');

        Config::set('mfa.identity_state.table', $table);

        $migration = require __DIR__ . '/../../database/migrations/2026_04_15_000001_create_mfa_identity_states_table.php';

        self::assertIsObject($migration);
        self::assertTrue(method_exists($migration, 'up') && method_exists($migration, 'down'));

        $migration->up();

        try {
            $unique = array_values(array_filter(
                Schema::getIndexes($table),
                static fn (array $index): bool => $index['unique'] && $index['columns'] === ['authenticatable_type', 'authenticatable_id'],
            ));

            self::assertCount(1, $unique);
            self::assertSame(substr($table, 0, 41) . '_' . substr(hash('sha256', $table), 0, 8) . '_owner_unique', $unique[0]['name']);
            self::assertSame(63, strlen($unique[0]['name']));
        } finally {
            $migration->down();
        }
    }
}
