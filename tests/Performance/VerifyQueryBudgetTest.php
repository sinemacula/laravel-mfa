<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Query-budget regression tests for the verification hot path.
 *
 * Codifies the maximum number of queries each branch of the manager's
 * verification lifecycle is allowed to issue. A new query that sneaks in
 * (eager-load, cache miss, N+1) trips these assertions before production does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class VerifyQueryBudgetTest extends TestCase
{
    use RefreshDatabase;

    /**
     * A successful TOTP verify must stay within the documented two-query
     * budget: the factor-row update plus the verification store write.
     *
     * @return void
     */
    public function testTotpVerifyHitBudget(): void
    {
        $user   = $this->loginUser();
        $secret = 'JBSWY3DPEHPK3PXP';

        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => $secret,
        ]);

        $google = new \PragmaRX\Google2FA\Google2FA;
        $code   = $google->getCurrentOtp($secret);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, $code),
        );

        // Budget: one update on the factor row for recordVerification +
        // one write to the verification store (session-backed, not a DB
        // connection in the default binding). Session writes happen via
        // the session driver, not the database — so the DB budget is 1.
        self::assertLessThanOrEqual(2, $count, sprintf(
            'TOTP verify hit exceeded query budget: %d queries',
            $count,
        ));
    }

    /**
     * Rejecting a verify against a locked factor must not issue any database
     * queries — the manager's lock check happens entirely in memory.
     *
     * @return void
     */
    public function testTotpVerifyLockedBudget(): void
    {
        $user = $this->loginUser();

        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            'locked_until'         => now()->addHour(),
        ]);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, '000000'),
        );

        // Locked factor: the manager rejects without touching the DB.
        self::assertSame(0, $count, sprintf(
            'Locked factor rejection issued queries: %d',
            $count,
        ));
    }

    /**
     * A failed TOTP verify must stay within a single query — the attempt-count
     * update on the factor row, with no verification store write.
     *
     * @return void
     */
    public function testTotpVerifyMissBudget(): void
    {
        $user = $this->loginUser();

        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, '000000'),
        );

        // One update on the factor row for recordAttempt. No verification
        // store write on failure.
        self::assertLessThanOrEqual(1, $count, sprintf(
            'TOTP verify miss exceeded query budget: %d queries',
            $count,
        ));
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
            'email'       => 'perf@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Count the queries issued while executing the given callback.
     *
     * @param  callable(): mixed  $callback
     * @return int
     */
    private function countQueries(callable $callback): int
    {
        DB::connection()->flushQueryLog();
        DB::connection()->enableQueryLog();

        try {
            $callback();
        } finally {
            DB::connection()->disableQueryLog();
        }

        /** @var list<array{query: string, bindings: list<mixed>, time: float|null}> $log */
        $log = DB::connection()->getQueryLog();

        return count($log);
    }
}
