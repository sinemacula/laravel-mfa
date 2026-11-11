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
 * Associates an identity's passkeys with factors. The credential itself is the
 * authentication layer's.
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
        $table  = TableNames::of(TableNames::PASSKEY_ASSOCIATIONS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::PASSKEY_ASSOCIATIONS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            $blueprint->string('factor_id');
            $blueprint->unique('factor_id', IndexName::for($table, '_factor_unique'));

            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');

            // Looked up by digest, as a 1023-byte id is beyond what MySQL
            // indexes. The unique index allows one association per credential.
            $blueprint->char('credential_id_hash', 64);
            $blueprint->text('credential_id');
            $blueprint->unique('credential_id_hash', IndexName::for($table, '_credential_unique'));
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_index'));

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::PASSKEY_ASSOCIATIONS));
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
