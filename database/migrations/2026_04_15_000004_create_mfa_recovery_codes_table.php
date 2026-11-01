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
 * Create the MFA recovery codes table: the codes of each identity's recovery
 * code set, stored as salted hashes.
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
        $table  = TableNames::of(TableNames::RECOVERY_CODES);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::RECOVERY_CODES . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // Plain string polymorphic columns, as on the factors table, so any
            // key type fits.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id', 'generation'], IndexName::for($table, '_owner_index'));

            // The salted hash of the code, never the code: long enough for any
            // of Laravel's hashers.
            $blueprint->string('code_hash');

            // The generation of the set the code belongs to: a newer set
            // replaces every code of an older one.
            $blueprint->unsignedInteger('generation');

            // When the code was used, or its set replaced; either ends it.
            $blueprint->timestamp('used_at')->nullable();
            $blueprint->timestamp('replaced_at')->nullable();

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::RECOVERY_CODES));
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
