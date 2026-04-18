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
 * Covers enrolment (one Factor row per code), single-use semantics, and the
 * atomic-consume race defence.
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
     * A backup code must verify successfully exactly once; the second attempt
     * against the same code must fail because the secret is consumed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
     * The atomic-consume path must defend against the stale-in-memory-copy
     * race: a second request still holding the pre-consumption snapshot must
     * fail even though its in-memory hash would otherwise match. We stage the
     * race by consuming through one handle, then verifying through an
     * independent handle whose attributes were snapshotted before consumption
     * — the in-memory hash still equals the expected secret, but the
     * conditional UPDATE finds a row whose stored secret is already null and
     * returns false.
     *
     * @return void
     *
     * @throws \Throwable
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

        // Snapshot a second, independently-loaded handle of the same row BEFORE
        // the first consumer runs — this models the concurrent shape where two
        // requests each loaded the factor and still believe the secret is
        // present.
        /** @var \SineMacula\Laravel\Mfa\Models\Factor $twinFactor */
        $twinFactor = Factor::query()->findOrFail($factor->getKey());

        $firstResult = $driver->verify($factor, $code);

        // Run the twin's verify against its stale snapshot. The in-memory hash
        // still matches, but the atomic UPDATE sees the nulled row and reports
        // failure.
        $secondResult = $driver->verify($twinFactor, $code);

        self::assertTrue($firstResult);
        self::assertFalse($secondResult);
    }

    /**
     * Create a fresh MFA-enrolled test user and authenticate as them for the
     * rest of the scenario.
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
