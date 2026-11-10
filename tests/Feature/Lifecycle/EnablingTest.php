<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Events\FactorEnabled;
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
 * Enabling a factor the failure ceiling disabled, for an actor: only the
 * disabling goes, its failures in a row and any lockout stay, and only a factor
 * that was disabled is enabled and reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleService::class)]
#[CoversClass(MfaManager::class)]
#[CoversClass(FactorEnabled::class)]
final class EnablingTest extends TestCase
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
     * A disabled factor is enabled, naming the actor and reporting it as it
     * stands once enabled; its failures in a row, its lockout and the
     * identity's run stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADisabledFactorIsEnabled(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $until  = CarbonImmutable::now()->addHour();

        $factor->update(['consecutive_failures' => 100, 'disabled_at' => CarbonImmutable::now(), 'locked_until' => $until]);

        IdentityState::query()->create(['authenticatable_type' => ProofOwner::of($user)->type, 'authenticatable_id' => ProofOwner::of($user)->key, 'consecutive_failures' => 7]);

        self::assertTrue(Mfa::enableFactor($user, $factor->id, self::actor()));
        self::assertSame(['FactorEnabled'], $this->reportedNames());
        self::assertInstanceOf(FactorEnabled::class, $this->reported[0]);
        self::assertSame($factor->id, $this->reported[0]->factor->id);
        self::assertFalse($this->reported[0]->factor->disabled);
        self::assertEquals(self::actor(), $this->reported[0]->actor);

        $stored = Factor::query()->whereKey($factor->id)->sole();

        self::assertNull($stored->getDisabledAt());
        self::assertSame(100, $stored->getConsecutiveFailures());
        self::assertSame($until->getTimestamp(), $stored->getLockedUntil()?->getTimestamp());
        self::assertSame(7, IdentityState::query()->where('authenticatable_id', ProofOwner::of($user)->key)->sole()->consecutive_failures);
    }

    /**
     * A factor that is not disabled is enabled again by nothing, and nothing is
     * reported, a second call included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorNotDisabledIsLeftAlone(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $factor->update(['consecutive_failures' => 3]);

        self::assertFalse(Mfa::enableFactor($user, $factor->id, self::actor()));

        $factor->update(['disabled_at' => CarbonImmutable::now()]);

        self::assertTrue(Mfa::enableFactor($user, $factor->id, self::actor()));
        self::assertFalse(Mfa::enableFactor($user, $factor->id, self::actor()));
        self::assertSame(['FactorEnabled'], $this->reportedNames());
        self::assertSame(3, Factor::query()->whereKey($factor->id)->sole()->getConsecutiveFailures());
    }

    /**
     * An id that finds none of the identity's factors enables and reports
     * nothing, another person's disabled factor included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdThatIsNotTheirsEnablesNothing(): void
    {
        $user = $this->signedInPerson();

        /** @var \Tests\Fixtures\Identities\TestUser $another */
        $another = TestUser::query()->create(['email' => 'another@example.test']);
        $theirs  = $this->confirmedFactor($another);

        $theirs->update(['disabled_at' => CarbonImmutable::now()]);

        foreach (['missing', $theirs->id, ['id' => $theirs->id]] as $id) {
            self::assertFalse(Mfa::enableFactor($user, $id, self::actor()));
        }

        self::assertSame([], $this->reportedNames());
        self::assertNotNull(Factor::query()->whereKey($theirs->id)->sole()->getDisabledAt());
        self::assertTrue(Mfa::enableFactor($another, $theirs->id, self::actor()));
    }

    /**
     * A model event that cancels the factor's save throws rather than reporting
     * a factor enabled that stays disabled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledSaveThrows(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $factor->update(['disabled_at' => CarbonImmutable::now()]);

        Factor::saving(static fn (): bool => false);

        try {
            Mfa::enableFactor($user, $factor->id, self::actor());
            self::fail('A cancelled save was expected to throw.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('the factor\'s save', $exception->getMessage());
        } finally {
            Factor::flushEventListeners();
        }

        self::assertNotNull(Factor::query()->whereKey($factor->id)->sole()->getDisabledAt());
        self::assertSame([], $this->reportedNames());
    }
}
