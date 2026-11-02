<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\AttemptKeys;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Enums\AttemptScope;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
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
 * Unlocking an identity or one of its factors, for an actor: only temporary
 * lockouts lift, the durable counts stay, a factor disabled at the failure
 * ceiling stays disabled, and only a live lockout lifted is reported.
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
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeLifecycle();
    }

    /**
     * A factor's live lockout lifts, naming the actor; its failures in a row
     * and its being disabled stay.
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

        $stored = Factor::query()->whereKey($factor->id)->sole();

        self::assertSame(4, $stored->getConsecutiveFailures());
        self::assertNotNull($stored->getDisabledAt());
        self::assertFalse(Mfa::unlockFactor($user, $factor->id, self::actor()));
        self::assertCount(1, $this->reported);
    }

    /**
     * An id that finds none of the identity's factors lifts and reports
     * nothing, another person's lockout included.
     *
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
     * The identity's live lockout lifts, naming the actor, and needs no caller;
     * its failures in a row stay. With none live nothing is reported.
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
     * A lockout already over clears without being reported as lifted.
     *
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
     * A model event that cancels the unlock's save throws rather than reporting
     * a lockout lifted that stays in force.
     *
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
        } catch (WriteCancelledException $exception) {
            self::assertStringContainsString('the identity\'s lockout', $exception->getMessage());
        } finally {
            IdentityState::flushEventListeners();
        }

        self::assertNotNull($this->state($user)->locked_until);
        self::assertSame([], $this->reportedNames());
    }

    /**
     * Lock the factor until an hour from now.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Factor  $factor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function lockFactor(Factor $factor): void
    {
        $this->container()->make(AttemptStore::class)->hold(
            $this->container()->make(AttemptKeys::class)->factor($factor->id),
            AttemptScope::FACTOR,
            5,
            CarbonImmutable::now()->getTimestamp() + 3600,
        );
    }

    /**
     * The identity's state row.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     */
    private function state(TestUser $user): IdentityState
    {
        return IdentityState::query()->where('authenticatable_id', ProofOwner::of($user)->key)->sole();
    }
}
