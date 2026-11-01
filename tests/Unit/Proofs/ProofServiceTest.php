<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Tests for `ProofService`: the current identity's verification is recorded,
 * forgotten and read through the bound store, and judged expired against the
 * window, failing closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofService::class)]
final class ProofServiceTest extends TestCase
{
    /**
     * Release the frozen clock and the Mockery expectations.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * A guest has never verified, is always expired, and records and forgets
     * nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestHasNoVerification(): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldNotReceive('lastVerifiedAt', 'markVerified', 'forget');

        $this->container()->instance(MfaVerificationStore::class, $store);

        self::assertFalse($this->service()->hasEverVerified());
        self::assertTrue($this->service()->hasExpired());

        $this->service()->markVerified();
        $this->service()->forgetVerification();
    }

    /**
     * The identity has verified once the store records a verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testHasEverVerifiedReadsTheStore(): void
    {
        $this->signIn();
        $this->storeAnswering(null);

        self::assertFalse($this->service()->hasEverVerified());

        $this->storeAnswering(Carbon::now());

        self::assertTrue($this->service()->hasEverVerified());
    }

    /**
     * Recording and forgetting a verification write through to the store for
     * the identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testMarkingAndForgettingWriteThroughToTheStore(): void
    {
        $user = $this->signIn();

        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('markVerified')->once()->with($user);
        $store->shouldReceive('forget')->once()->with($user);

        $this->container()->instance(MfaVerificationStore::class, $store);

        $this->service()->markVerified();
        $this->service()->forgetVerification();
    }

    /**
     * Without a recorded verification the identity is expired.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutAVerificationTheIdentityIsExpired(): void
    {
        $this->signIn();
        $this->storeAnswering(null);

        self::assertTrue($this->service()->hasExpired(60));
    }

    /**
     * Ages of a verification, windows, and whether it is expired.
     *
     * @return iterable<string, array{int, ?int, bool}>
     */
    public static function windows(): iterable
    {
        yield 'just now' => [0, 60, false];
        yield 'at the window' => [60, 60, false];
        yield 'past the window' => [61, 60, true];
        yield 'in the future' => [-5, 60, true];
        yield 'a zero window' => [0, 0, true];
        yield 'a negative window' => [0, -1, true];
        yield 'at the configured window' => [30, null, false];
        yield 'past the configured window' => [31, null, true];
    }

    /**
     * A verification is expired once more minutes than the window have passed,
     * or when it is dated in the future.
     *
     * @param  int  $minutesAgo
     * @param  ?int  $window
     * @param  bool  $expired
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('windows')]
    public function testExpiryAgainstAGivenWindow(int $minutesAgo, ?int $window, bool $expired): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        config()->set('mfa.default_expiry', 30);

        $this->signIn();
        $this->storeAnswering(Carbon::now()->subMinutes($minutesAgo));

        self::assertSame($expired, $this->service()->hasExpired($window));
    }

    /**
     * Without a configured window, a verification lasts the default fourteen
     * days.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheDefaultWindowIsFourteenDays(): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        $config = $this->container()->make('config');
        $mfa    = $config->get('mfa');

        self::assertIsArray($mfa);

        unset($mfa['default_expiry']);
        $config->set('mfa', $mfa);

        $this->signIn();

        $this->storeAnswering(Carbon::now()->subMinutes(20160));
        self::assertFalse($this->service()->hasExpired());

        $this->storeAnswering(Carbon::now()->subMinutes(20161));
        self::assertTrue($this->service()->hasExpired());
    }

    /**
     * A malformed window fails closed: every verification is expired.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAMalformedWindowExpiresEveryVerification(): void
    {
        Carbon::setTestNow('2026-10-31 12:00:00');

        config()->set('mfa.default_expiry', 'forever');

        $this->signIn();
        $this->storeAnswering(Carbon::now());

        self::assertTrue($this->service()->hasExpired());
    }

    /**
     * Resolve the proof service.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): ProofService
    {
        return $this->container()->make(ProofService::class);
    }

    /**
     * Bind a store whose last verification is the given time.
     *
     * @param  ?\Carbon\Carbon  $at
     * @return void
     */
    private function storeAnswering(?Carbon $at): void
    {
        $store = \Mockery::mock(MfaVerificationStore::class);
        $store->shouldReceive('lastVerifiedAt')->andReturn($at);

        $this->container()->instance(MfaVerificationStore::class, $store);
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @return \Tests\Fixtures\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\TestUser $user */
        $user = TestUser::query()->create(['email' => 'proof@example.com']);

        $this->actingAs($user);

        return $user;
    }
}
