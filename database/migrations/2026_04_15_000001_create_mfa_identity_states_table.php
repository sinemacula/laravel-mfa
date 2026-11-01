<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Mfa\Database\IndexName;
use SineMacula\Laravel\Mfa\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * Create the MFA identity states table: one row per identity that owns factors,
 * holding its factor state as a whole, and the row every change to that state
 * locks first.
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
        $table  = TableNames::of(TableNames::IDENTITY_STATES);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::IDENTITY_STATES . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // Plain string polymorphic columns, as on the factors table, so any
            // key type fits. One row per identity: the lock that serialises
            // changes to its factor state is taken by inserting or updating
            // this row, which the unique index makes a single row per owner.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->unique(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_unique'));

            // Advanced to invalidate every proof recorded under an earlier
            // generation, so other sessions must verify again.
            $blueprint->unsignedBigInteger('verification_generation')->default(0);

            // Whether a reset obliges the identity to enrol again at its next
            // sign-in, until a factor is confirmed.
            $blueprint->boolean('reenrollment_required')->default(false);

            // The identity's consecutive failures across all its factors, and
            // the lockout they applied.
            $blueprint->unsignedInteger('consecutive_failures')->default(0);
            $blueprint->timestamp('locked_until')->nullable();

            // The generation of the identity's current recovery code set and
            // when it was generated.
            $blueprint->unsignedInteger('recovery_codes_generation')->default(0);
            $blueprint->timestamp('recovery_codes_generated_at')->nullable();

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::IDENTITY_STATES));
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
};
