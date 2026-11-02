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
use SineMacula\Laravel\Mfa\Verification\Submission;
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
     * A successful TOTP verify on a signed-in session must stay within its
     * documented budget of twenty-two queries, each a read or write of one row
     * by key.
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
            'status'               => 'confirmed',
        ]);

        $code = AuthenticatorApp::code($factor);

        $count = $this->countQueries(
            static fn () => Mfa::verify(Submission::factor($factor->id, $code)),
        );

        // Budget: the factor found (1); the IP slot, an update and an insert
        // for its first window (2); the identity state lock and the factors
        // locked under it, for the verification and again for the attempt
        // counted in it (4); the admission's first factor, whose declared proof
        // and recorded proofs each read the verification generation (3), and
        // its state and lockout reads (2); the attempt's state and lockout
        // reads (2); the accepted step's compare-and-set and the factor's last
        // use (2); the proof's generation (1); the session's proofs and
        // declared first factor for the evaluation (3); the re-enrolment
        // obligation (1); and the slot given back (1). The proof itself is
        // written to the session, not the database.
        self::assertLessThanOrEqual(
            22,
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
            'status'               => 'confirmed',
            'consecutive_failures' => 5,
        ]);

        $this->container()->make(AttemptStore::class)->hold(
            $this->container()->make(AttemptKeys::class)->factor($factor->id),
            AttemptScope::FACTOR,
            5,
            now()->addHour()->getTimestamp(),
        );

        $count = $this->countQueries(
            static fn () => Mfa::verify(Submission::factor($factor->id, '000000')),
        );

        // Locked factor: the factor found, the IP slot taken and given back (3,
        // with its first window), the identity state lock and its factors (2),
        // the admission's first factor (3) and its state and lockout reads (2).
        // The code is never checked, so nothing is counted or proved.
        self::assertLessThanOrEqual(
            11,
            $count,
            sprintf('Locked factor rejection issued queries: %d', $count),
        );
    }

    /**
     * A failed TOTP verify on a signed-in session must stay within eighteen
     * queries: the reads and locks of a hit before the code is checked, the
     * identity's failure counted in its window and its state row, and the
     * factor's failure in a row, with no step recorded and no proof.
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
            'status'               => 'confirmed',
        ]);

        $count = $this->countQueries(
            static fn () => Mfa::verify(Submission::factor($factor->id, '000000')),
        );

        // The fourteen reads and locks of a hit before the code is checked, the
        // identity's window counted in one upsert and read back, its state row
        // and the factor row updated. No code matches, so no step is recorded,
        // and the IP slot is kept, not given back. No proof is made on failure.
        self::assertLessThanOrEqual(
            18,
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
        config()->set('mfa.applications.web', ['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

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
