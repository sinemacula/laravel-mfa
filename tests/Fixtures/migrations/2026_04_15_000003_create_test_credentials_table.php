<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A stand-in for an authentication layer's passkey credentials table.
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
        Schema::create('test_credentials', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('owner');
            $blueprint->text('credential_id');
        });
    }

    /**
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('test_credentials');
    }
};
