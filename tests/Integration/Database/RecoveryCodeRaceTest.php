<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus;
use SineMacula\Laravel\Mfa\RecoveryCodes\Redemption;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\RecoveryCodes\CountingHasher;
use Tests\TestCase;

/**
 * Recovery codes redeemed and replaced concurrently, on MySQL and PostgreSQL.
 *
 * The package's tables live on the default connection, which a second
 * connection to the same database, `observer`, stands in for a concurrent
 * request on, with a lock timeout of a second. While one redemption checks the
 * set, a parallel redemption of the same code cannot read it: it waits for the
 * identity's state lock and times out; once the first has committed, the
 * parallel one finds the code used, so the code passes once. While a new set
 * replaces the old one, a concurrent reader sees the old set whole, and a
 * parallel redemption waits for the lock; once the replacement has committed,
 * the old codes fail and the new ones redeem, so there is never a moment when
 * both sets work or neither does.
 *
 * SQLite serialises every writer on the whole file, so these tests run on the
 * server databases only; the same guarantees are proved on one connection by
 * the unit tests of the recovery code service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeRaceTest extends TestCase
{
    /** @var ?\Throwable What stopped the parallel request, if anything did. */
    private ?\Throwable $stopped = null;

    /** @var ?\SineMacula\Laravel\Mfa\RecoveryCodes\Redemption How the parallel redemption ended, if it did. */
    private ?Redemption $parallel = null;

    /**
     * Skip on SQLite, and give the observer a lock timeout of a second.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $driver = DB::connection()->getDriverName();

        if (!in_array($driver, ['mysql', 'pgsql'], true)) {
            self::markTestSkipped('Concurrent recovery code redemptions are proven on MySQL and PostgreSQL.');
        }

        DB::connection('observer')->statement($driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : 'SET lock_timeout = \'1s\'');
    }

    /**
     * Of two concurrent redemptions of one code, the second waits for the first
     * to commit, then finds the code used: the code passes once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConcurrentRedemptionOfOneCodePassesOnce(): void
    {
        $holder = $this->signIn();
        $code   = $this->generate($holder)[0]->reveal();
        $hasher = $this->countChecks();

        $hasher->before(function () use ($holder, $code): void {
            $this->redeemAsObserver($holder, $code);
        });

        $first = $this->service()->redeem($holder, $code, self::bound($holder));

        self::assertTrue($first->passed);
        self::assertNull($this->parallel);
        self::assertInstanceOf(QueryException::class, $this->stopped);

        $this->stopped = null;

        $this->redeemAsObserver($holder, $code);

        self::assertNull($this->stopped);
        self::assertInstanceOf(Redemption::class, $this->parallel);
        self::assertFalse($this->parallel->passed);
        self::assertSame(FailureReason::INVALID_CODE, $this->parallel->reason);
        self::assertSame(1, RecoveryCode::query()->whereNotNull('used_at')->count());
    }

    /**
     * While a new set replaces the old one, a concurrent reader sees the old
     * set whole and a concurrent redemption waits; once the replacement has
     * committed, the old codes fail and the new ones redeem.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacementIsSeenWholeOrNotAtAll(): void
    {
        $holder = $this->signIn();
        $old    = $this->generate($holder)[0]->reveal();
        $seen   = null;
        $stored = 0;

        RecoveryCode::creating(function () use ($holder, $old, &$seen, &$stored): void {
            if (++$stored !== 5) {
                return;
            }

            $seen = $this->asObserver(fn (): RecoveryCodeStatus => $this->service()->status($holder));

            $this->redeemAsObserver($holder, $old);
        });

        $current = $this->generate($holder)[0]->reveal();

        self::assertInstanceOf(RecoveryCodeStatus::class, $seen);
        self::assertSame(10, $seen->remaining);
        self::assertSame(1, $seen->generation);
        self::assertNull($this->parallel);
        self::assertInstanceOf(QueryException::class, $this->stopped);

        $this->stopped = null;

        $this->redeemAsObserver($holder, $old);

        self::assertInstanceOf(Redemption::class, $this->parallel);
        self::assertFalse($this->parallel->passed);

        $this->redeemAsObserver($holder, $current);

        self::assertInstanceOf(Redemption::class, $this->parallel);
        self::assertTrue($this->parallel->passed);
        self::assertSame(2, $this->service()->status($holder)->generation);
    }

    /**
     * Add the observer, a second connection to the test database, accept
     * recovery codes on the `web` application and hash cheaply.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(Repository::class);

        $config->set('database.connections.observer', $config->get('database.connections.testing'));
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.applications.web', [
            'recovery_codes' => ['enabled' => true],
            'first_factor'   => ['method' => 'password', 'channel' => 'password'],
        ]);
    }

    /**
     * Redeem the code on the observer, as a concurrent request would, noting
     * how it ended or what stopped it.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @param  string  $code
     * @return void
     *
     * @throws \Throwable
     */
    private function redeemAsObserver(FactorHolder $holder, string $code): void
    {
        try {
            $this->parallel = $this->asObserver(fn (): Redemption => $this->service()->redeem($holder, $code, self::bound($holder)));
        } catch (QueryException $exception) {
            $this->stopped = $exception;
        }
    }

    /**
     * What a redemption by the identity is bound to.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function bound(FactorHolder $holder): ProofBinding
    {
        return new ProofBinding($holder->getMorphClass(), (string) $holder->id, 'web', 'race-sign-in', Purpose::SIGN_IN);
    }

    /**
     * Run the callback with the package's tables reached through the observer.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    private function asObserver(\Closure $callback): mixed
    {
        config()->set('mfa.storage.connection', 'observer');

        try {
            return $callback();
        } finally {
            config()->set('mfa.storage.connection', null);
        }
    }

    /**
     * Count the hasher's checks from now on, handing each to the real hasher.
     *
     * @return \Tests\Fixtures\RecoveryCodes\CountingHasher
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function countChecks(): CountingHasher
    {
        $hasher = new CountingHasher($this->container()->make(Hasher::class));

        $this->container()->instance(Hasher::class, $hasher);

        return $hasher;
    }

    /**
     * Generate a set for the identity.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $holder
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \Throwable
     */
    private function generate(FactorHolder $holder): array
    {
        return $this->service()->generate($holder);
    }

    /**
     * Create an identity with a confirmed factor and sign it in.
     *
     * @return \Tests\Fixtures\Identities\FactorHolder
     */
    private function signIn(): FactorHolder
    {
        /** @var \Tests\Fixtures\Identities\FactorHolder $holder */
        $holder = FactorHolder::query()->create(['email' => 'race@example.com']);

        Factor::query()->create([
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        Auth::login($holder);

        return $holder;
    }

    /**
     * Resolve the recovery code service.
     *
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): RecoveryCodeService
    {
        return $this->container()->make(RecoveryCodeService::class);
    }
}
