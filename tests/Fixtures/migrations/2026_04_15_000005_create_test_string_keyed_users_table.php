<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Identities under a UUID or ULID key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

return new class extends Migration {
    /**
     * @return void
     */
    public function up(): void
    {
        Schema::create('test_string_keyed_users', static function (Blueprint $blueprint): void {
            $blueprint->string('id', 36)->primary();
            $blueprint->string('email')->nullable();
            $blueprint->string('password')->nullable();
            $blueprint->string('remember_token', 100)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('test_string_keyed_users');
    }
};
