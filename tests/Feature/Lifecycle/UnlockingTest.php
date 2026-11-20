<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\TestCase;

/**
 * Unlocking lifts only temporary lockouts; durable counts and a ceiling
 * disabling stay, and only a live lockout lifted is reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleService::class)]
#[CoversClass(AttemptService::class)]
#[CoversClass(MfaManager::class)]
final class UnlockingTest extends TestCase
{
    use ArrangesLifecycle;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeLifecycle();
    }

    /**
     * Its failures in a row and its being disabled stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorsLockoutLifts(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $factor->update(['consecutive_failures' => 4, 'disabled_at' => CarbonImmutable::now()]);

        $this->lockFactor($factor);

        self::assertTrue(Mfa::unlockFactor($user, $factor->id, self::actor()));
        self::assertSame(['LockoutLifted'], $this->reportedNames());
        self::assertInstanceOf(LockoutLifted::class, $this->reported[0]);
        self::assertSame($factor->id, $this->reported[0]->factor?->id);
        self::assertEquals(self::actor(), $this->reported[0]->actor);
        self::assertNull($this->reported[0]->context()['ip']);
        self::assertNull($this->reported[0]->context()['user_agent']);

        $stored = Factor::query()->whereKey($factor->id)->sole();

        self::assertSame(4, $stored->getConsecutiveFailures());
        self::assertNotNull($stored->getDisabledAt());
        self::assertFalse(Mfa::unlockFactor($user, $factor->id, self::actor()));
        self::assertCount(1, $this->reported);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdThatIsNotTheirsLiftsNothing(): void
    {
        $user = $this->signedInPerson();

        /** @var \Tests\Fixtures\Identities\TestUser $another */
        $another = TestUser::query()->create(['email' => 'another@example.test']);
        $theirs  = $this->confirmedFactor($another);

        $this->lockFactor($theirs);

        foreach (['missing', $theirs->id, ['id' => $theirs->id]] as $id) {
            self::assertFalse(Mfa::unlockFactor($user, $id, self::actor()));
        }

        self::assertSame([], $this->reportedNames());
        self::assertTrue(Mfa::unlockFactor($another, $theirs->id, self::actor()));
    }

    /**
     * It needs no caller and its failures in a row stay; with none live nothing
     * is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentitysLockoutLifts(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        self::assertFalse(Mfa::unlockIdentity($user, self::actor()));

        $this->state($user)->update(['locked_until' => CarbonImmutable::now()->addHour(), 'consecutive_failures' => 3]);

        self::assertTrue(Mfa::unlockIdentity($user, self::actor()));
        self::assertSame(['LockoutLifted'], $this->reportedNames());
        self::assertInstanceOf(LockoutLifted::class, $this->reported[0]);
        self::assertNull($this->reported[0]->factor);
        self::assertEquals(self::actor(), $this->reported[0]->actor);

        $state = $this->state($user);

        self::assertNull($state->locked_until);
        self::assertSame(3, $state->consecutive_failures);
        self::assertFalse(Mfa::unlockIdentity($user, self::actor()));
    }

    /**
     * The factor's and the identity's lift both carry it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnlockCarriesTheClientGiven(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $client = new ClientContext('198.51.100.4', 'Admin/1.0');

        $this->lockFactor($factor);

        self::assertTrue(Mfa::unlockFactor($user, $factor->id, self::actor(), $client));

        $this->state($user)->update(['locked_until' => CarbonImmutable::now()->addHour()]);

        self::assertTrue(Mfa::unlockIdentity($user, self::actor(), $client));
        self::assertCount(2, $this->reported);

        foreach ($this->reported as $event) {
            self::assertSame('198.51.100.4', $event->context()['ip']);
            self::assertSame('Admin/1.0', $event->context()['user_agent']);
        }
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockoutAlreadyOverIsNotReported(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        self::assertFalse(Mfa::unlockIdentity($user, self::actor()));

        $this->state($user)->update(['locked_until' => CarbonImmutable::now()->subHour()]);

        self::assertFalse(Mfa::unlockIdentity($user, self::actor()));
        self::assertNull($this->state($user)->locked_until);
        self::assertSame([], $this->reportedNames());
    }

    /**
     * With no lockout to lift nothing is reported, yet the window's count is
     * gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUnlockingWithNoLockoutStillClearsTheWindow(): void
    {
        config()->set('mfa.attempts.identity_limit', 5);

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        $this->failTimes($user, 4);

        self::assertFalse(Mfa::unlockIdentity($user, self::actor()));
        self::assertSame([], $this->reportedNames());
        $this->assertTheWindowStartsAgain($user);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetClearsTheWindow(): void
    {
        config()->set('mfa.attempts.identity_limit', 5);

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        $this->failTimes($user, 4);

        Mfa::resetIdentity($user, self::actor(), 'Lost phone.');

        $this->assertTheWindowStartsAgain($user);
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledSaveThrows(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'person@example.test']);

        self::assertFalse(Mfa::unlockIdentity($user, self::actor()));

        $until = CarbonImmutable::now()->addHour();

        $this->state($user)->update(['locked_until' => $until]);

        IdentityState::saving(static fn (): bool => false);

        try {
            Mfa::unlockIdentity($user, self::actor());
            self::fail('A cancelled save was expected to throw.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('the identity\'s lockout', $exception->getMessage());
        } finally {
            IdentityState::flushEventListeners();
        }

        self::assertNotNull($this->state($user)->locked_until);
        self::assertSame([], $this->reportedNames());
    }

    /**
     * Four failures under a limit of five leave it unlocked, and a fifth locks
     * it.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     *
     * @throws \Throwable
     */
    private function assertTheWindowStartsAgain(TestUser $user): void
    {
        $this->failTimes($user, 4);

        self::assertNull($this->attempts()->lockout($user));

        $this->failTimes($user, 1);

        self::assertNotNull($this->attempts()->lockout($user));
    }

    /**
     * Recovery code failures, which count against the identity alone.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $times
     * @return void
     *
     * @throws \Throwable
     */
    private function failTimes(TestUser $user, int $times): void
    {
        for ($i = 0; $i < $times; $i++) {
            $this->attempts()->attempt(new Attempt($user, null, Purpose::SIGN_IN), static fn (): bool => false);
        }
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Attempts\AttemptService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function attempts(): AttemptService
    {
        return $this->container()->make(AttemptService::class);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     */
    private function lockFactor(Factor $factor): void
    {
        $factor->update(['locked_until' => CarbonImmutable::now()->addHour()]);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function state(TestUser $user): IdentityState
    {
        return IdentityState::query()->where('authenticatable_id', ProofOwner::of($user)->key)->sole();
    }
}
