<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * An application's own recovery codes table, with its own column names.
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
        Schema::create('test_recovery_codes', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('owner_type');
            $blueprint->string('owner_id');
            $blueprint->string('hash');
            $blueprint->unsignedInteger('set_number');
            $blueprint->timestamp('redeemed_at')->nullable();
            $blueprint->timestamp('retired_at')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('test_recovery_codes');
    }
};
