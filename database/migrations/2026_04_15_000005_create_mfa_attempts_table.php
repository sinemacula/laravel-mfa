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
 * Create the MFA attempts table: the temporary throttles, one counter per scope
 * (a factor, an identity or an IP address) and subject, counted with atomic
 * upserts so no cache is needed.
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
        $table  = TableNames::of(TableNames::ATTEMPTS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::ATTEMPTS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            // HMAC-SHA256 hex digest, keyed from the application key, of the
            // scope and the subject it counts, so the table alone gives neither
            // back.
            $blueprint->char('key', 64)->primary();

            // The scope the counter counts within: a factor, an identity or an
            // IP address.
            $blueprint->string('scope', 16);

            $blueprint->unsignedInteger('hits');

            // When the counter's window ends, indexed for pruning ended
            // windows.
            $blueprint->timestamp('window_ends_at')->index(IndexName::for($table, '_window_index'));
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
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::ATTEMPTS));
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
