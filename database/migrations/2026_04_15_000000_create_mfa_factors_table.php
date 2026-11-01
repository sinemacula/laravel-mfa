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
 * Create the MFA factors table: one row per factor an identity has enrolled or
 * is enrolling.
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
     * @throws \SineMacula\Laravel\Mfa\Exceptions\TableAlreadyExistsException
     */
    public function up(): void
    {
        $table  = TableNames::of(TableNames::FACTORS);
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table, TableNames::FACTORS . '.table');

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->ulid('id')->primary();

            // Plain string polymorphic columns so the table works against
            // integer, UUID, or ULID identity keys. `morphs()` would pin the id
            // to unsignedBigInteger and break non-integer keys.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id'], IndexName::for($table, '_owner_index'));

            // The name the factor's driver is registered under (`totp`,
            // `email`, `sms`, `passkey` or an application's own).
            $blueprint->string('type', 64);

            // The label the person chose, such as "Work phone".
            $blueprint->string('label')->nullable();

            // The phone number (E.164) or email address an SMS or email factor
            // delivers to, captured when it is enrolled and never resolved live
            // from the identity, so a changed address cannot redirect codes.
            $blueprint->string('destination')->nullable();

            // The credential a passkey factor is associated with. Text, since a
            // WebAuthn credential id reaches 1023 bytes.
            $blueprint->text('credential_reference')->nullable();

            // The TOTP shared secret, encrypted at rest by the model's cast,
            // and the parameters the factor was enrolled with, so it keeps
            // working the same way after the configuration changes.
            $blueprint->text('secret')->nullable();
            $blueprint->string('totp_algorithm', 16)->nullable();
            $blueprint->unsignedTinyInteger('totp_digits')->nullable();
            $blueprint->unsignedSmallInteger('totp_period')->nullable();

            // The last time step a TOTP code was accepted for: the same or an
            // earlier step is refused.
            $blueprint->unsignedBigInteger('last_accepted_step')->nullable();

            // Pending until a first valid code or assertion confirms it; only a
            // confirmed factor is usable.
            $blueprint->string('status', 16)->default('pending');
            $blueprint->boolean('preferred')->default(false);

            // The durable consecutive-failure count, reset only by a success of
            // this factor, and when the failure ceiling disabled the factor.
            $blueprint->unsignedInteger('consecutive_failures')->default(0);
            $blueprint->timestamp('disabled_at')->nullable();

            // The application the factor was enrolled through: an application's
            // limits on new enrolments count only its own.
            $blueprint->string('application')->nullable();

            $blueprint->timestamp('confirmed_at')->nullable();
            $blueprint->timestamp('last_used_at')->nullable();

            // The delivered code and its expiry, encrypted at rest by the
            // model's cast, until delivered codes have a table of their own.
            $blueprint->text('code')->nullable();
            $blueprint->timestamp('expires_at')->nullable();

            // The per-factor attempt counter and lockout, until the attempt
            // throttles replace them, and when verification was last attempted.
            $blueprint->unsignedInteger('attempts')->default(0);
            $blueprint->timestamp('locked_until')->nullable();
            $blueprint->timestamp('last_attempted_at')->nullable();

            $blueprint->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::connection($this->getConnection())->dropIfExists(TableNames::of(TableNames::FACTORS));
    }

    /**
     * The connection the package's tables live on (see `StorageConnection`),
     * the one the model reads and writes the table on.
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
