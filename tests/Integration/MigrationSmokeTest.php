<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * Engine-agnostic migration smoke test.
 *
 * Asserts that the shipped `mfa_factors` table exists with every
 * expected column and the polymorphic-lookup index after the package
 * migration runs end-to-end. Catches engine-specific schema bugs that
 * would otherwise ship behind a green badge — e.g. a column type
 * MySQL accepts but PostgreSQL rejects, or an index name that
 * collides with a reserved identifier on one engine.
 *
 * The "database-tests" CI matrix runs this against MySQL and
 * PostgreSQL (with `DB_CONNECTION` exported); local runs hit
 * in-memory SQLite by default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MigrationSmokeTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Every column the manager + drivers read or write must exist on
     * the freshly migrated `mfa_factors` table — this is the schema
     * contract the rest of the test suite implicitly assumes.
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
     * The polymorphic lookup path (`Mfa::getFactors()` and the manager
     * cache) reads `WHERE authenticatable_type = ? AND
     * authenticatable_id = ?` on every request. The index that backs
     * that query must exist, regardless of engine.
     *
     * @return void
     */
    public function testFactorsTableHasPolymorphicLookupIndex(): void
    {
        $columns = Schema::getIndexes('mfa_factors');

        $hasMorphIndex = false;

        foreach ($columns as $index) {
            $cols = $index['columns'] ?? [];

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
}
