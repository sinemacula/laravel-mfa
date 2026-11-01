<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Mfa\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * Create the MFA identity states table: one row per identity that owns factors,
 * the row every change to the identity's whole factor state locks first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException
     */
    public function up(): void
    {
        $table = Config::string('mfa.identity_state.table', 'mfa_identity_states') ?: 'mfa_identity_states';

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, 'identity_state.table');

        $index = $this->ownerIndex($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($index): void {
            $blueprint->ulid('id')->primary();

            // Plain string polymorphic columns, as on the factors table, so any
            // key type fits. One row per identity: the lock that serialises
            // changes to its factor state is taken by inserting or updating
            // this row, which the unique index makes a single row per owner.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->unique(['authenticatable_type', 'authenticatable_id'], $index);

            $blueprint->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function down(): void
    {
        $table = Config::string('mfa.identity_state.table', 'mfa_identity_states') ?: 'mfa_identity_states';

        Schema::connection($this->getConnection())->dropIfExists($table);
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one every serialised change locks this table's rows on.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[Override]
    public function getConnection(): ?string
    {
        return StorageConnection::name();
    }

    /**
     * The name of the one-row-per-owner index: the table's name with a suffix,
     * or, when that would pass the 63 characters PostgreSQL keeps (MySQL keeps
     * 64), the start of the table's name and a hash of the whole, so a long
     * configured name still gives one index name, the same on every run.
     *
     * @param  string  $table
     * @return string
     */
    private function ownerIndex(string $table): string
    {
        $suffix = '_owner_unique';
        $index  = $table . $suffix;

        if (strlen($index) <= 63) {
            return $index;
        }

        $hash = substr(hash('sha256', $table), 0, 8);

        return substr($table, 0, 63 - strlen($suffix) - strlen($hash) - 1) . '_' . $hash . $suffix;
    }
};
