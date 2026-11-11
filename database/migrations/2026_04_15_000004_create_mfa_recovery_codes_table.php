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
 * Each identity's recovery code set, stored as salted hashes.
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
        $table  = TableNames::of(TableNames::RECOVERY_CODES);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::RECOVERY_CODES . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id', 'generation'], IndexName::for($table, '_owner_index'));

            // Long enough for any of Laravel's hashers.
            $blueprint->string('code_hash');

            $blueprint->unsignedInteger('generation');

            $blueprint->timestamp('used_at')->nullable();
            $blueprint->timestamp('replaced_at')->nullable();

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::RECOVERY_CODES));
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
