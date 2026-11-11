<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Factors under an integer key, for a factor model that does not use ULIDs.
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
        Schema::create('test_integer_keyed_factors', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('authenticatable_type');
            $blueprint->string('authenticatable_id');
            $blueprint->string('type', 64);
            $blueprint->string('label')->nullable();
            $blueprint->string('status', 16)->default('pending');
            $blueprint->boolean('preferred')->default(false);
            $blueprint->unsignedInteger('consecutive_failures')->default(0);
            $blueprint->string('application')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('test_integer_keyed_factors');
    }
};
