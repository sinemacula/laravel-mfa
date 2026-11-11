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
 * One row per enrolment in progress, binding its pending factor to its grant.
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
        $table  = TableNames::of(TableNames::ENROLLMENTS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::ENROLLMENTS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            $blueprint->string('factor_id');
            $blueprint->unique('factor_id', IndexName::for($table, '_factor_unique'));

            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_index'));

            // Never the grant itself.
            $blueprint->char('grant_hash', 64);
            $blueprint->unique('grant_hash', IndexName::for($table, '_grant_unique'));

            // Advancing the generation kills the grant; the session is a keyed
            // digest.
            $blueprint->string('application');
            $blueprint->string('session_id');
            $blueprint->unsignedInteger('generation');
            $blueprint->string('authority', 32);

            $blueprint->string('challenge_id')->nullable();

            // Never renewed.
            $blueprint->timestamp('expires_at')->index(IndexName::for($table, '_expiry_index'));
            $blueprint->unsignedInteger('attempts')->default(0);

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::ENROLLMENTS));
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
