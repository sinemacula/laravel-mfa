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
        $table = Config::string('mfa.factor.table', 'mfa_factors');

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

            // Persistent secret for drivers that use one (TOTP). Encrypted
            // at rest via the model's `encrypted` cast.
            $blueprint->text('secret')->nullable();

            // Currently issued one-time code (email, SMS) and its expiry.
            // Cleared after successful verification or when the next
            // challenge is issued. Bounded to 32 chars — enough for any
            // realistic OTP alphabet / length, small enough to defend
            // against oversized input and keep the index cheap.
            $blueprint->string('code', 32)->nullable();
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
        $table = Config::string('mfa.factor.table', 'mfa_factors');

        Schema::dropIfExists($table);
    }
};
