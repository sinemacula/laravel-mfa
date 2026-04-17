<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\NoopFactorDriver;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * `Mfa::issueBackupCodes()` end-to-end lifecycle.
 *
 * Closes the package's first-party recovery-code workflow: the
 * manager mints a fresh batch, atomically replaces any prior batch,
 * persists only the hashed value, dispatches an enrolment event per
 * code, and surfaces the plaintext set exactly once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class IssueBackupCodesTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Without an authenticated MFA-capable identity, the call must
     * be a no-op (returns `[]`) rather than throw — matches the
     * established `enrol()` / `disable()` shape so consumers can call
     * it unconditionally during onboarding flows.
     *
     * @return void
     */
    public function testReturnsEmptyArrayWhenNoIdentity(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        self::assertSame([], Mfa::issueBackupCodes());

        Event::assertNotDispatched(MfaFactorEnrolled::class);
        self::assertCount(0, Factor::query()->get());
    }

    /**
     * The default call mints the configured number of codes, persists
     * one Factor row per code with a hashed `secret`, returns the
     * plaintext set exactly once, and dispatches one
     * `MfaFactorEnrolled` event per code.
     *
     * @return void
     */
    public function testMintsAndPersistsConfiguredBatch(): void
    {
        $user = $this->loginUser();

        Event::fake([MfaFactorEnrolled::class]);

        $codes = Mfa::issueBackupCodes();

        self::assertCount(10, $codes);
        self::assertContainsOnlyString($codes);

        $persisted = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('driver', 'backup_code')
            ->get();

        self::assertCount(10, $persisted);

        $hasher = new BackupCodeDriver;

        foreach ($codes as $code) {
            // Plaintext codes must NOT be persisted — only their hash.
            self::assertCount(
                0,
                $persisted->where('secret', $code),
                'plaintext code must not appear in the persisted secret column',
            );
            // The hashed counterpart must be present exactly once.
            self::assertCount(
                1,
                $persisted->where('secret', $hasher->hash($code)),
                'every minted code must be persisted as a hashed factor row',
            );
        }

        Event::assertDispatchedTimes(MfaFactorEnrolled::class, 10);
    }

    /**
     * A second call atomically replaces the prior batch — every
     * pre-existing backup-code row is deleted before the new ones are
     * minted, so there is no overlap window where both batches would
     * verify.
     *
     * @return void
     */
    public function testRotationDeletesPriorBatch(): void
    {
        $user = $this->loginUser();

        $first = Mfa::issueBackupCodes();
        self::assertCount(10, $first);

        $firstIds = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('driver', 'backup_code')
            ->pluck('id')
            ->all();
        self::assertCount(10, $firstIds);

        $second = Mfa::issueBackupCodes();
        self::assertCount(10, $second);

        $secondIds = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('driver', 'backup_code')
            ->pluck('id')
            ->all();

        self::assertCount(10, $secondIds);
        self::assertEmpty(
            array_intersect($firstIds, $secondIds),
            'second batch must replace the first — no shared row IDs',
        );

        // None of the original plaintext codes should still verify.
        self::assertEmpty(array_intersect($first, $second));
    }

    /**
     * Passing an explicit `$count` argument overrides the configured
     * default batch size for that single call.
     *
     * @return void
     */
    public function testHonoursExplicitCountArgument(): void
    {
        $this->loginUser();

        $codes = Mfa::issueBackupCodes(3);

        self::assertCount(3, $codes);
        self::assertCount(3, Factor::query()->where('driver', 'backup_code')->get());
    }

    /**
     * Rotation must run inside a database transaction — partial state
     * (old rows deleted but new ones not inserted, or vice versa) is
     * never visible to a concurrent reader. The "single winner"
     * concurrency invariant is verified by issuing a fresh batch and
     * confirming the row count is exactly the new batch size.
     *
     * @return void
     */
    public function testFinalRowCountReflectsExactlyTheNewBatch(): void
    {
        $user = $this->loginUser();

        // Pre-seed an unrelated factor (TOTP) — rotation must not
        // delete factors of other drivers.
        Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        Mfa::issueBackupCodes();

        $totp = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('driver', 'totp')
            ->get();
        $backup = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->where('driver', 'backup_code')
            ->get();

        self::assertCount(1, $totp, 'rotation must not touch other drivers');
        self::assertCount(10, $backup);
    }

    /**
     * Rotation invalidates the manager's per-identity cache so the
     * next `Mfa::isSetup()` reflects the new batch immediately.
     *
     * @return void
     */
    public function testRotationInvalidatesSetupCache(): void
    {
        $this->loginUser();

        // Warm the cache to "no factors".
        self::assertFalse(Mfa::isSetup());

        Mfa::issueBackupCodes();

        // Without the cache invalidation this assertion would still
        // see the stale `false` value.
        self::assertTrue(Mfa::isSetup());
    }

    /**
     * If a consumer has overridden the shipped `backup_code` driver
     * with something that is not a `BackupCodeDriver` subclass, the
     * manager refuses to mint codes against it — the rotation flow
     * relies on the driver's hashing primitive and would otherwise
     * silently corrupt state.
     *
     * @return void
     */
    public function testThrowsWhenBackupCodeDriverWasOverriddenWithIncompatibleImplementation(): void
    {
        $this->loginUser();

        // Replace the bound driver with a no-op that does not extend
        // `BackupCodeDriver` — `issueBackupCodes()` must reject it
        // rather than silently bypass the rotation invariants.
        Mfa::extend('backup_code', static fn (): FactorDriver => new NoopFactorDriver);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(BackupCodeDriver::class);

        Mfa::issueBackupCodes();
    }

    /**
     * Authenticate as a fresh MFA-enabled test user and return them.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function loginUser(): TestUser
    {
        $user = TestUser::create([
            'email'       => 'backup-rotation@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }
}
