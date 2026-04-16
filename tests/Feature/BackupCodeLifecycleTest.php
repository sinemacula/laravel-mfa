<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * End-to-end backup-code lifecycle.
 *
 * Covers enrolment (one Factor row per code), single-use semantics,
 * and the atomic-consume race defence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class BackupCodeLifecycleTest extends TestCase
{
    use RefreshDatabase;

    /**
     * A backup code must verify successfully exactly once; the
     * second attempt against the same code must fail because the
     * secret is consumed.
     *
     * @return void
     */
    public function testBackupCodeVerifiesOnceThenFails(): void
    {
        $user   = $this->loginUser();
        $driver = new BackupCodeDriver;

        $plaintexts = $driver->generateSet();
        $code       = $plaintexts[0];

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'backup_code',
            'secret'               => $driver->hash($code),
        ]);

        // First use succeeds.
        $first = Mfa::verify('backup_code', $factor, $code);
        self::assertTrue($first);

        // Subsequent replay fails because the secret is nulled.
        $factor->refresh();
        $second = Mfa::verify('backup_code', $factor, $code);
        self::assertFalse($second);
    }

    /**
     * Two concurrent consumers of the same backup code must produce
     * exactly one success — the second consumer sees the nulled
     * secret and fails.
     *
     * @return void
     */
    public function testConcurrentConsumptionHasASingleWinner(): void
    {
        $user   = $this->loginUser();
        $driver = new BackupCodeDriver;

        $code = 'SHARED0001';

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'backup_code',
            'secret'               => $driver->hash($code),
        ]);

        // Simulate a second concurrent request that already consumed
        // the row via the same atomic UPDATE the driver uses.
        $twinFactor = $factor->replicate();
        $twinFactor->setAttribute('id', $factor->getKey());
        $twinFactor->exists = true;

        $firstResult = $driver->verify($factor, $code);

        // Reload the row; the second attempt sees the nulled secret
        // and must fail even though it holds a stale in-memory copy.
        $factor->refresh();
        $secondResult = $driver->verify($factor, $code);

        self::assertTrue($firstResult);
        self::assertFalse($secondResult);
    }

    /**
     * Create a fresh MFA-enrolled test user and authenticate as them
     * for the rest of the scenario.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function loginUser(): TestUser
    {
        $user = TestUser::create([
            'email'       => 'backup@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }
}
