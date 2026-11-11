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
 * Codes sent by SMS or email, stored as keyed hashes.
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
        $table  = TableNames::of(TableNames::CODES);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::CODES . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            $blueprint->string('factor_id');

            // So an identity's codes are found without its factors.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_index'));

            // The session is a keyed digest, never the id.
            $blueprint->string('purpose', 32);
            $blueprint->string('application');
            $blueprint->string('session_id')->nullable();
            $blueprint->index(['factor_id', 'purpose', 'session_id'], IndexName::for($table, '_binding_index'));

            // Outlives the factor, so a restarted enrolment's sends stay
            // counted.
            $blueprint->char('destination_hash', 64);
            $blueprint->index(['destination_hash', 'sent_at'], IndexName::for($table, '_destination_index'));

            // Keyed from `app.key`, never the code.
            $blueprint->char('code_hash', 64);

            // `sent_times` is a JSON list of Unix times the send caps count.
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
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::CODES));
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
