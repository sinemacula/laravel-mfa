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
 * Create the MFA codes table: the codes sent by SMS or email, stored as a keyed
 * hash bound to their factor, purpose, application and session.
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
        $table  = TableNames::of(TableNames::CODES);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::CODES . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // The factor the code was sent for.
            $blueprint->string('factor_id');

            // Plain string polymorphic columns, as on the factors table, so any
            // key type fits, and so an identity's codes are found without its
            // factors.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_index'));

            // What the code is bound to: it is accepted only for the same
            // factor, purpose, application and session. The session is stored
            // as a keyed digest of its id, never the id itself.
            $blueprint->string('purpose', 32);
            $blueprint->string('application');
            $blueprint->string('session_id')->nullable();
            $blueprint->index(['factor_id', 'purpose', 'session_id'], IndexName::for($table, '_binding_index'));

            // HMAC-SHA256 hex digest of the code and its binding, keyed from
            // the application key, never the code.
            $blueprint->char('code_hash', 64);

            // The attempts made against the code, how many times it was sent,
            // when last and when each time (a JSON list of Unix times, which
            // the send caps count), when it expires (indexed for pruning) and
            // when it was used.
            $blueprint->unsignedInteger('attempts')->default(0);
            $blueprint->unsignedInteger('sends')->default(1);
            $blueprint->timestamp('sent_at');
            $blueprint->json('sent_times');
            $blueprint->timestamp('expires_at')->index(IndexName::for($table, '_expiry_index'));
            $blueprint->timestamp('consumed_at')->nullable();

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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::CODES));
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
