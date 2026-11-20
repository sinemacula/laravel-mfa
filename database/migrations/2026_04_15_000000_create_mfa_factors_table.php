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
 * One row per factor an identity has enrolled or is enrolling.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException
     */
    public function up(): void
    {
        $table  = TableNames::of(TableNames::FACTORS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::FACTORS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // Plain strings, not `morphs()`, so UUID and ULID keys fit. Owners
            // are found by their hash, as a collation may ignore case.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->char('owner_hash', 64);
            $blueprint->index('owner_hash', IndexName::for($table, '_owner_index'));

            // The driver name: `totp`, `email`, `sms`, `passkey` or custom.
            $blueprint->string('type', 64);

            $blueprint->string('label')->nullable();

            // Captured at enrolment, never read live from the identity, so a
            // changed address cannot redirect codes.
            $blueprint->string('destination')->nullable();

            // Text, since a WebAuthn credential id reaches 1023 bytes.
            $blueprint->text('credential_reference')->nullable();

            // The secret is encrypted by the model's cast; the parameters are
            // kept so a configuration change does not alter the factor.
            $blueprint->text('secret')->nullable();
            $blueprint->string('totp_algorithm', 16)->nullable();
            $blueprint->unsignedTinyInteger('totp_digits')->nullable();
            $blueprint->unsignedSmallInteger('totp_period')->nullable();

            // The same or an earlier TOTP step is refused.
            $blueprint->unsignedBigInteger('last_accepted_step')->nullable();

            $blueprint->string('status', 16)->default('pending');
            $blueprint->boolean('preferred')->default(false);

            // Reset only by a success of this factor.
            $blueprint->unsignedInteger('consecutive_failures')->default(0);
            $blueprint->dateTime('disabled_at')->nullable();

            // On the locked row, so an attempt reads it as committed.
            $blueprint->dateTime('locked_until')->nullable();

            // An application's enrolment limits count only its own factors.
            $blueprint->string('application')->nullable();

            $blueprint->dateTime('confirmed_at')->nullable();
            $blueprint->dateTime('last_used_at')->nullable();

            $blueprint->datetimes();
        });
    }

    /**
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::FACTORS));
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
