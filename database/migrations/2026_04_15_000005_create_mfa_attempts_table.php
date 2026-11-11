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
 * Attempt throttles, one counter per scope and subject, counted atomically so
 * no cache is needed.
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
        $table  = TableNames::of(TableNames::ATTEMPTS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::ATTEMPTS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            // Keyed from `app.key`, so the table alone reveals no subject.
            $blueprint->char('key', 64)->primary();

            $blueprint->string('scope', 16);

            $blueprint->unsignedInteger('hits');

            $blueprint->timestamp('window_ends_at')->index(IndexName::for($table, '_window_index'));
        });
    }

    /**
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::ATTEMPTS));
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
