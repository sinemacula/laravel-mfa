<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\MfaFactorDisabled;
use SineMacula\Laravel\Mfa\Events\MfaFactorEnrolled;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Identities\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
 * Unit tests for `MfaManager` lifecycle mutations.
 *
 * Covers `enroll()` and `disable()`. Split out from the broader state-test
 * family so each subject stays under the project's max-methods-per-class
 * threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerLifecycleTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerState;

    /**
     * Without an identity `enroll()` must not persist the factor or dispatch
     * the lifecycle event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollIsNoopWhenNoIdentity(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        $factor = $this->makeUnpersistedTotpFactor();

        $this->manager()->enroll($factor);

        Event::assertNotDispatched(MfaFactorEnrolled::class);
        self::assertFalse($factor->exists);
    }

    /**
     * Test enroll() persists the supplied factor row.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollPersistsFactor(): void
    {
        $user    = $this->makeEnrollUser();
        $factor  = $this->makeUnpersistedTotpFactor($user);
        $manager = $this->manager();

        $manager->enroll($factor);

        self::assertTrue($factor->exists, 'enroll() must persist the factor row');
    }

    /**
     * Test enroll() dispatches the MfaFactorEnrolled event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollDispatchesEnrolledEvent(): void
    {
        Event::fake([MfaFactorEnrolled::class]);

        $user    = $this->makeEnrollUser();
        $factor  = $this->makeUnpersistedTotpFactor($user);
        $manager = $this->manager();

        $manager->enroll($factor);

        Event::assertDispatched(
            MfaFactorEnrolled::class,
            static fn (MfaFactorEnrolled $event): bool => $event->identity === $user
                && $event->factor                                          === $factor
                && $event->driver                                          === 'totp',
        );
    }

    /**
     * Test isSetup() sees a factor enroll() persisted at once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEnrollIsSeenByIsSetupAtOnce(): void
    {
        $user    = $this->makeEnrollUser();
        $manager = $this->manager();

        self::assertFalse($manager->isSetup());

        $manager->enroll($this->makeUnpersistedTotpFactor($user));

        self::assertTrue($manager->isSetup(), 'isSetup() must see the enrolled factor');
    }

    /**
     * Without an identity `disable()` must not delete the factor or dispatch
     * the lifecycle event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableIsNoopWhenNoIdentity(): void
    {
        Event::fake([MfaFactorDisabled::class]);

        $user = TestUser::query()->create([
            'email'       => 'orphan-disable@example.test',
            'mfa_enabled' => true,
        ]);

        // Persist a factor but do NOT actingAs() — disable() should
        // short-circuit on the missing identity.
        $factor = $this->persistTotpFactorFor($user);

        $this->manager()->disable($factor);

        Event::assertNotDispatched(MfaFactorDisabled::class);
        self::assertNotNull(Factor::query()->find($factor->getKey()));
    }

    /**
     * Test disable deletes the underlying factor row.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableDeletesFactorRow(): void
    {
        [$manager, $factor] = $this->enrollAndResolveFactor();

        $manager->disable($factor);

        self::assertNull(
            Factor::query()->find($factor->getKey()),
            'disable() must delete the factor row',
        );
    }

    /**
     * Test disable dispatches the MfaFactorDisabled event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableDispatchesDisabledEvent(): void
    {
        Event::fake([MfaFactorDisabled::class]);

        [$manager, $factor, $user] = $this->enrollAndResolveFactor();

        $manager->disable($factor);

        Event::assertDispatched(
            MfaFactorDisabled::class,
            static fn (MfaFactorDisabled $event): bool => $event->identity === $user
                && $event->driver                                          === 'totp',
        );
    }

    /**
     * Test isSetup() sees a factor disable() removed at once.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableIsSeenByIsSetupAtOnce(): void
    {
        [$manager, $factor] = $this->enrollAndResolveFactor();

        self::assertTrue($manager->isSetup());

        $manager->disable($factor);

        self::assertFalse($manager->isSetup(), 'isSetup() must no longer see the disabled factor');
    }

    /**
     * Test disable stops every proof made with the factor counting on the
     * current sign-in, and keeps the proofs of other factors.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDisableStopsTheFactorsProofsCounting(): void
    {
        [$manager, $factor, $user] = $this->enrollAndResolveFactor();

        Auth::login($user);

        $store   = $this->container()->make(ProofStore::class);
        $session = $store->currentSession($user, 'web');

        self::assertIsString($session);

        $factorId = $factor->getKey();

        self::assertIsString($factorId);

        foreach ([$factorId, 'another-factor'] as $reference) {
            $store->record(new Proof(
                ProofKind::ADDITIONAL_FACTOR,
                'totp',
                new Channel(ChannelKind::AUTHENTICATOR_APP, $reference),
                $reference,
                ObservedProperties::none(),
                CarbonImmutable::now(),
                new ProofBinding(TestUser::class, (string) $user->id, 'web', $session, Purpose::STEP_UP),
                0,
            ));
        }

        $manager->disable($factor);

        self::assertSame(['another-factor'], array_map(static fn (Proof $proof): ?string => $proof->reference, $manager->proofs()));
    }

    /**
     * Build a fresh TOTP `Factor` model that is NOT yet persisted — the
     * consumer-side shape that `enroll()` is intended to receive.
     *
     * @param  ?\Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function makeUnpersistedTotpFactor(?TestUser $user = null): Factor
    {
        $factor         = new Factor;
        $factor->type   = 'totp';
        $factor->secret = 'JBSWY3DPEHPK3PXP';

        if ($user !== null) {
            $factor->authenticatable_type = $user::class;
            $factor->authenticatable_id   = (string) $user->id;
        }

        return $factor;
    }

    /**
     * Create an MFA-enabled user and authenticate as them, returning the user
     * for enrol-flow tests.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function makeEnrollUser(): TestUser
    {
        $user = TestUser::query()->create([
            'email'       => 'enroll@example.test',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Persist a TOTP factor against the supplied identity and return the row.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function persistTotpFactorFor(TestUser $user): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);
    }

    /**
     * Enrol an MFA-enabled user with a TOTP factor and return the manager,
     * resolved factor, and user triple for disable-flow tests.
     *
     * @formatter:off
     *
     * @return array{0: \SineMacula\Laravel\Mfa\MfaManager, 1: \SineMacula\Laravel\Mfa\Models\Factor, 2: \Tests\Fixtures\Identities\TestUser}
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function enrollAndResolveFactor(): array
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::query()
            ->where('authenticatable_id', (string) $user->id)
            ->sole();

        return [$manager, $factor, $user];
    }
}
