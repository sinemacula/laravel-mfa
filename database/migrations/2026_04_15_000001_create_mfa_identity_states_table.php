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
 * One row of factor state per identity, locked first by every change to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
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

            // The unique index keeps one row per owner, which the factor state
            // lock upserts.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->unique(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_unique'));

            // Advanced to invalidate every earlier proof.
            $blueprint->unsignedBigInteger('verification_generation')->default(0);

            // Set by a reset until a factor is confirmed.
            $blueprint->boolean('reenrollment_required')->default(false);

            // Across every factor.
            $blueprint->unsignedInteger('consecutive_failures')->default(0);
            $blueprint->timestamp('locked_until')->nullable();

            $blueprint->unsignedInteger('recovery_codes_generation')->default(0);
            $blueprint->timestamp('recovery_codes_generated_at')->nullable();

            $blueprint->timestamps();
        });
    }

    /**
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::IDENTITY_STATES));
    }

    /**
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
