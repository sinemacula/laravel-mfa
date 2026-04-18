<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Mfa\Database\MigrationCollisionGuard;

/**
 * Create the MFA factors table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorTableAlreadyExistsException
     */
    public function up(): void
    {
        $table = self::resolveTable();

        $schema = Schema::getConnection()->getSchemaBuilder();

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        Schema::create($table, static function (Blueprint $blueprint): void {
            $blueprint->ulid('id')->primary();

            // Plain string polymorphic columns so the table works against
            // integer, UUID, or ULID identity keys. `morphs()` would pin the id
            // to unsignedBigInteger and break non-integer keys.
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->index(['authenticatable_type', 'authenticatable_id']);

            // Driver name this factor is registered against (e.g. 'totp',
            // 'email', 'sms', 'backup_code'). Indexed because a single
            // identity may have multiple factors and lookups typically
            // filter by driver.
            $blueprint->string('driver')->index();

            // Optional human-readable label (e.g. "Work phone", "Authy").
            // Surfaced in the structured exception payload and UI flows to
            // disambiguate between multiple factors of the same driver.
            $blueprint->string('label')->nullable();

            // Delivery destination for OTP-delivery drivers. Stores the phone
            // number for SMS factors (E.164-formatted), email address for
            // email factors, and is null for factors that don't deliver to
            // the identity over the network (TOTP, backup codes). Captured
            // at enrolment time — intentionally not resolved live from the
            // identity so a silent address change cannot redirect codes.
            $blueprint->string('recipient')->nullable();

            // Persistent secret for drivers that use one (TOTP). Encrypted
            // at rest via the model's `encrypted` cast.
            $blueprint->text('secret')->nullable();

            // Currently issued one-time code (email, SMS) and its expiry.
            // Cleared after successful verification or when the next
            // challenge is issued. Encrypted at rest via the model's
            // `encrypted` cast — `text` rather than a fixed length so
            // the encrypted ciphertext fits regardless of the configured
            // OTP alphabet / length.
            $blueprint->text('code')->nullable();
            $blueprint->timestamp('expires_at')->nullable();

            // Rate-limiting state. `attempts` is reset on successful
            // verification or new challenge issuance. `locked_until` is set
            // when the configured max-attempts threshold is reached and
            // cleared on unlock. `last_attempted_at` is set on every verify
            // call regardless of outcome.
            $blueprint->unsignedInteger('attempts')->default(0);
            $blueprint->timestamp('locked_until')->nullable();
            $blueprint->timestamp('last_attempted_at')->nullable();

            // When the factor last completed a successful verification.
            // `null` means the factor has never been verified (new
            // enrolment).
            $blueprint->timestamp('verified_at')->nullable();

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
        Schema::dropIfExists(self::resolveTable());
    }

    /**
     * Read the configured factor table, treating a missing or empty config
     * value as `'mfa_factors'`. Mirrors the shipped `Factor` model's
     * `resolveConfiguredTable()` so migrate-up and migrate-down see the same
     * table name even when the consumer has set the config to an empty string.
     *
     * @return string
     */
    private static function resolveTable(): string
    {
        $table = Config::string('mfa.factor.table', 'mfa_factors');

        return $table === '' ? 'mfa_factors' : $table;
    }
};
