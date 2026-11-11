<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException;
use Tests\TestCase;

/**
 * Schema checks run against MySQL and PostgreSQL in CI to catch engine-specific
 * schema bugs; local runs use in-memory SQLite.
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
     * @return iterable<string, array{string, list<string>}>
     */
    public static function tables(): iterable
    {
        $owner = ['authenticatable_type', 'authenticatable_id'];

        yield 'mfa_factors' => ['mfa_factors', [
            'id', ...$owner, 'type', 'label', 'destination', 'credential_reference', 'secret', 'totp_algorithm', 'totp_digits',
            'totp_period', 'last_accepted_step', 'status', 'preferred', 'consecutive_failures', 'disabled_at', 'locked_until',
            'application', 'confirmed_at', 'last_used_at', 'created_at', 'updated_at',
        ]];
        yield 'mfa_identity_states' => ['mfa_identity_states', [
            'id', ...$owner, 'verification_generation', 'reenrollment_required', 'consecutive_failures', 'locked_until',
            'recovery_codes_generation', 'recovery_codes_generated_at', 'created_at', 'updated_at',
        ]];
        yield 'mfa_enrollments' => ['mfa_enrollments', [
            'id', 'factor_id', ...$owner, 'grant_hash', 'application', 'session_id', 'expires_at', 'attempts', 'created_at', 'updated_at',
        ]];
        yield 'mfa_codes' => ['mfa_codes', [
            'id', 'factor_id', ...$owner, 'purpose', 'application', 'session_id', 'destination_hash', 'code_hash', 'attempts', 'sends', 'sent_at',
            'sent_times', 'expires_at', 'consumed_at', 'created_at', 'updated_at',
        ]];
        yield 'mfa_recovery_codes' => ['mfa_recovery_codes', [
            'id', ...$owner, 'code_hash', 'generation', 'used_at', 'replaced_at', 'created_at', 'updated_at',
        ]];
        yield 'mfa_attempts' => ['mfa_attempts', ['key', 'scope', 'hits', 'window_ends_at']];
        yield 'mfa_passkey_associations' => ['mfa_passkey_associations', [
            'id', 'factor_id', ...$owner, 'credential_id_hash', 'credential_id', 'created_at', 'updated_at',
        ]];
    }

    /**
     * @param  string  $table
     * @param  list<string>  $columns
     * @return void
     */
    #[DataProvider('tables')]
    public function testEveryTableHasEveryRequiredColumn(string $table, array $columns): void
    {
        self::assertTrue(Schema::hasTable($table));
        self::assertSame([], array_values(array_diff($columns, Schema::getColumnListing($table))), sprintf('Missing columns on %s after migration.', $table));
    }

    /**
     * A delivered code lives in the codes table as a keyed hash.
     *
     * @return void
     */
    public function testTheFactorsTableHoldsNoDeliveredCode(): void
    {
        self::assertFalse(Schema::hasColumn('mfa_factors', 'code'));
        self::assertFalse(Schema::hasColumn('mfa_factors', 'expires_at'));
    }

    /**
     * @return iterable<string, array{string, list<string>}>
     */
    public static function uniqueIndexes(): iterable
    {
        yield 'one enrolment per factor' => ['mfa_enrollments', ['factor_id']];
        yield 'one enrolment per grant' => ['mfa_enrollments', ['grant_hash']];
        yield 'one association per factor' => ['mfa_passkey_associations', ['factor_id']];
        yield 'one association per credential' => ['mfa_passkey_associations', ['credential_id_hash']];
        yield 'one counter per key' => ['mfa_attempts', ['key']];
    }

    /**
     * @param  string  $table
     * @param  list<string>  $columns
     * @return void
     */
    #[DataProvider('uniqueIndexes')]
    public function testTheUniqueIndexesExist(string $table, array $columns): void
    {
        $unique = array_filter(
            Schema::getIndexes($table),
            static fn (array $index): bool => $index['unique'] && $index['columns'] === $columns,
        );

        self::assertCount(1, $unique, sprintf('Expected a unique index on %s (%s).', $table, implode(', ', $columns)));
    }

    /**
     * Column defaults give a pending, unpreferred factor and zeroed counts.
     *
     * @return void
     */
    public function testNewRowsTakeTheSafeDefaults(): void
    {
        DB::table('mfa_factors')->insert(['id' => '01JFACTOR00000000000000000', 'authenticatable_type' => 'user', 'authenticatable_id' => '1', 'type' => 'totp']);
        DB::table('mfa_identity_states')->insert(['id' => '01JSTATE000000000000000000', 'authenticatable_type' => 'user', 'authenticatable_id' => '1']);

        $factor = (array) DB::table('mfa_factors')->first();
        $state  = (array) DB::table('mfa_identity_states')->first();

        self::assertSame(['pending', 0, 0], [$factor['status'], (int) $factor['preferred'], (int) $factor['consecutive_failures']]);
        self::assertSame(
            [0, 0, 0, 0],
            [(int) $state['verification_generation'], (int) $state['reenrollment_required'], (int) $state['consecutive_failures'], (int) $state['recovery_codes_generation']],
        );
    }

    /**
     * A table that already exists is refused with its setting's name.
     *
     * @return void
     */
    public function testEachTableTakesItsConfiguredName(): void
    {
        Config::set('mfa.codes.table', 'delivered_codes');

        $migration = require __DIR__ . '/../../database/migrations/2026_04_15_000003_create_mfa_codes_table.php';

        self::assertIsObject($migration);
        self::assertTrue(method_exists($migration, 'up') && method_exists($migration, 'down'));

        $migration->up();

        try {
            self::assertTrue(Schema::hasTable('delivered_codes'));
            self::assertSame(['delivered_codes_owner_index', 'delivered_codes_binding_index', 'delivered_codes_expiry_index'], array_values(array_intersect(
                ['delivered_codes_owner_index', 'delivered_codes_binding_index', 'delivered_codes_expiry_index'],
                array_column(Schema::getIndexes('delivered_codes'), 'name'),
            )));

            $this->expectException(TableAlreadyExistsException::class);
            $this->expectExceptionMessage('Set `codes.table` in config/mfa.php');

            $migration->up();
        } finally {
            $migration->down();

            self::assertFalse(Schema::hasTable('delivered_codes'));
        }
    }

    /**
     * Every factor read filters on the owner's type and identifier.
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
     * The factor state lock upserts against this unique index.
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
     * The index name is truncated and hashed to fit every engine's limit.
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
