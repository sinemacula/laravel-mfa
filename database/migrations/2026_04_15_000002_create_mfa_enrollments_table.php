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
 * Create the MFA enrolments table: one row per enrolment in progress, binding
 * its pending factor to the grant that may confirm it.
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
        $table  = TableNames::of(TableNames::ENROLLMENTS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::ENROLLMENTS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // The pending factor this enrolment confirms: one enrolment per
            // factor.
            $blueprint->string('factor_id');
            $blueprint->unique('factor_id', IndexName::for($table, '_factor_unique'));

            // Plain string polymorphic columns, as on the factors table, so any
            // key type fits.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_index'));

            // SHA-256 hex digest of the enrolment grant, never the grant.
            $blueprint->char('grant_hash', 64);
            $blueprint->unique('grant_hash', IndexName::for($table, '_grant_unique'));

            // What the grant is bound to: the application, a keyed digest of
            // the sign-in that started the enrolment, the verification
            // generation it started under, so advancing that kills the grant,
            // and what authorised it.
            $blueprint->string('application');
            $blueprint->string('session_id');
            $blueprint->unsignedInteger('generation');
            $blueprint->string('authority', 32);

            // The challenge the last delivered code went out under, written
            // once it has been sent.
            $blueprint->string('challenge_id')->nullable();

            // When the grant stops confirming, taken once from what authorised
            // it and never renewed, indexed for pruning abandoned enrolments,
            // and the confirmation attempts made against it.
            $blueprint->timestamp('expires_at')->index(IndexName::for($table, '_expiry_index'));
            $blueprint->unsignedInteger('attempts')->default(0);

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::ENROLLMENTS));
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the package reads and writes the table on.
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
