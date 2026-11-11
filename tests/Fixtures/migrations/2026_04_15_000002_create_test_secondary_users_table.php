<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A second users table, for factor scoping across two identity classes.
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
        Schema::create('test_secondary_users', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->nullable();
            $blueprint->boolean('mfa_enabled')->default(false);
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
        Schema::dropIfExists('test_secondary_users');
    }
};
