<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Query-budget regression tests for the verification hot path.
 *
 * Codifies the maximum number of queries each branch of the manager's
 * verification lifecycle is allowed to issue. A new query that sneaks in
 * (eager-load, cache miss, N+1) trips these assertions before production does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(TotpDriver::class)]
final class VerifyQueryBudgetTest extends TestCase
{
    use RefreshDatabase;

    /**
     * A successful TOTP verify on a signed-in session must stay within the
     * documented ten-query budget: the IP address's slot taken and given back,
     * the identity's state lock and its factors, the identity's state and the
     * factor's lockout read under the lock, the verification generation its
     * proof carries, the accepted step's compare-and-set and the factor-row
     * update.
     *
     * @return void
     */
    public function testTotpVerifyHitBudget(): void
    {
        $user = $this->loginUser();

        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
        ]);

        $code = AuthenticatorApp::code($factor);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, $code),
        );

        // Budget: the IP slot (an update, and an insert for its first window),
        // the identity state lock and the factors locked under it, the identity
        // state and the factor lockout read under the lock, one read of the
        // identity's verification generation, taken before the code is checked
        // and carried by the proof, one conditional update recording the
        // accepted time step, one update on the factor row for
        // recordVerification, and the slot given back. The proof itself is
        // written to the session, not the database.
        self::assertLessThanOrEqual(
            10,
            $count,
            sprintf('TOTP verify hit exceeded query budget: %d queries', $count),
        );
    }

    /**
     * Rejecting a verify against a locked factor reads the lockout under the
     * identity's lock, from the write connection, and writes nothing but the IP
     * address's slot, which it gives back.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function testTotpVerifyLockedBudget(): void
    {
        $user = $this->loginUser();

        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'consecutive_failures' => 5,
        ]);

        $this->container()->make(AttemptStore::class)->hold(
            $this->container()->make(AttemptKeys::class)->factor($factor->id),
            AttemptScope::FACTOR,
            5,
            now()->addHour()->getTimestamp(),
        );

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, '000000'),
        );

        // Locked factor: the IP slot taken and given back, the identity state
        // lock and its factors, and the identity state and factor lockout
        // reads; the code is never checked, so the verification generation is
        // never read, and nothing is counted or proved.
        self::assertLessThanOrEqual(
            7,
            $count,
            sprintf('Locked factor rejection issued queries: %d', $count),
        );
    }

    /**
     * A failed TOTP verify on a signed-in session must stay within eleven
     * queries: the reads and locks of a hit, including the verification
     * generation read before the code is checked, the identity's failure
     * counted in its window and its state row, and the factor's failure in a
     * row, with no step recorded and no proof.
     *
     * @return void
     */
    public function testTotpVerifyMissBudget(): void
    {
        $user = $this->loginUser();

        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
        ]);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, '000000'),
        );

        // The seven reads and locks of a hit before the code is checked, the
        // identity's window counted in one upsert and read back, its state row
        // and the factor row updated. No code matches, so no step is recorded,
        // and the IP slot is kept, not given back. No proof is recorded on
        // failure.
        self::assertLessThanOrEqual(
            11,
            $count,
            sprintf('TOTP verify miss exceeded query budget: %d queries', $count),
        );
    }

    /**
     * Create a fresh MFA-enrolled test user and sign them in for the rest of
     * the scenario, so a verification has a sign-in to record its proof on.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function loginUser(): TestUser
    {
        $user = TestUser::create([
            'email'       => 'perf@example.test',
            'mfa_enabled' => true,
        ]);

        Auth::login($user);

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
