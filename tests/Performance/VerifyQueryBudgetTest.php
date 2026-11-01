<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
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
     * A successful TOTP verify must stay within the documented eight-query
     * budget: the IP address's slot taken and given back, the identity's state
     * lock and its factors, the identity's state and the factor's lockout read
     * under the lock, and the factor-row update.
     *
     * @return void
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testTotpVerifyHitBudget(): void
    {
        $user   = $this->loginUser();
        $secret = 'JBSWY3DPEHPK3PXP';

        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => $secret,
        ]);

        $google = new Google2FA;
        $code   = $google->getCurrentOtp($secret);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, $code),
        );

        // Budget: the IP slot (an update, and an insert for its first window),
        // the identity state lock and the factors locked under it, the identity
        // state and the factor lockout read under the lock, the slot given
        // back, and one update on the factor row for recordVerification. The
        // verification store is session-backed, not a database connection in
        // the default binding.
        self::assertLessThanOrEqual(
            8,
            $count,
            sprintf('TOTP verify hit exceeded query budget: %d queries', $count),
        );
    }

    /**
     * Rejecting a verify against a locked factor reads the lockout under the
     * identity's lock, from the write connection, and writes nothing but the
     * IP address's slot, which it gives back.
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
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
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
        // reads; the driver never runs and nothing is counted.
        self::assertLessThanOrEqual(
            7,
            $count,
            sprintf('Locked factor rejection issued queries: %d', $count),
        );
    }

    /**
     * A failed TOTP verify must stay within eleven queries: the reads and locks
     * of a hit, the identity's failure counted in its window and its state row,
     * and the factor's failure in a row, with no verification store write.
     *
     * @return void
     */
    public function testTotpVerifyMissBudget(): void
    {
        $user = $this->loginUser();

        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $count = $this->countQueries(
            static fn () => Mfa::verify('totp', $factor, '000000'),
        );

        // The six reads and locks of a hit before the driver, the identity's
        // window counted (an update, and an insert for its first window) and
        // read back, its state row and the factor row updated. The IP slot is
        // kept, not given back. No verification store write on failure.
        self::assertLessThanOrEqual(
            11,
            $count,
            sprintf('TOTP verify miss exceeded query budget: %d queries', $count),
        );
    }

    /**
     * Create a fresh MFA-enrolled test user and authenticate as them for the
     * rest of the scenario.
     *
     * @return \Tests\Fixtures\Identities\TestUser
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
