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
 * Create the MFA passkey associations table: which of an identity's passkeys
 * are associated with it as factors. A passkey is a factor only through such a
 * record; the credential itself is the authentication layer's.
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
        $table  = TableNames::of(TableNames::PASSKEY_ASSOCIATIONS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::PASSKEY_ASSOCIATIONS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // The factor the passkey is associated as: one association per
            // factor.
            $blueprint->string('factor_id');
            $blueprint->unique('factor_id', IndexName::for($table, '_factor_unique'));

            // Plain string polymorphic columns, as on the factors table, so any
            // key type fits.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');

            // A credential id reaches 1023 bytes, beyond what MySQL indexes as
            // text, so it is found by the SHA-256 hex digest of its bytes and
            // kept in full beside it. A credential is associated at most once
            // per identity.
            $blueprint->char('credential_id_hash', 64);
            $blueprint->text('credential_id');
            $blueprint->unique(['authenticatable_type', 'authenticatable_id', 'credential_id_hash'], IndexName::for($table, '_credential_unique'));

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::PASSKEY_ASSOCIATIONS));
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
