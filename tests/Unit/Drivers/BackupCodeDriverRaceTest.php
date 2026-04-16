<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Race-condition unit tests for `BackupCodeDriver::verify()`.
 *
 * Exercises the pessimistic-lock branch that triggers when the factor
 * row disappears (or a concurrent request already consumed the secret)
 * between the in-memory hash compare and the transaction lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class BackupCodeDriverRaceTest extends TestCase
{
    use RefreshDatabase;

    public function testConsumeReturnsFalseWhenRowVanishes(): void
    {
        $user = TestUser::create([
            'email'       => 'race@example.test',
            'mfa_enabled' => true,
        ]);

        $driver = new BackupCodeDriver;
        $code   = 'RACEA0001X';

        /** @var Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->getKey(),
            'driver'               => 'backup_code',
            'secret'               => $driver->hash($code),
        ]);

        // Simulate a concurrent request deleting the row after the
        // in-memory read in verify() but before the transaction lock.
        // Delete directly via the query builder so our in-memory
        // $factor still holds its stale state.
        Factor::query()->whereKey($factor->getKey())->delete();

        $result = $driver->verify($factor, $code);

        self::assertFalse($result);
    }
}
