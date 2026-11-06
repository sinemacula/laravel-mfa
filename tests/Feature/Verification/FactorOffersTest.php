<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\InvertedActiveState;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * The factors offered to a session are the identity's confirmed ones of an
 * enabled type that can succeed after its first factor, the preferred first, as
 * summaries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorOffers::class)]
#[CoversClass(PasskeyAssertions::class)]
final class FactorOffersTest extends TestCase
{
    use ArrangesVerification;

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The preferred factor comes first, then the oldest, then by id.
     *
     * @return void
     */
    public function testTheOffersAreOrdered(): void
    {
        $user = $this->signedInPerson();

        $newest    = $this->totpFactor($user, ['label' => 'newest']);
        $preferred = $this->emailFactor($user, attributes: ['preferred' => true, 'label' => 'preferred']);

        $newest->forceFill(['created_at' => CarbonImmutable::now()->addHour()])->save();

        $oldest = $this->totpFactor($user, ['label' => 'oldest']);

        $oldest->forceFill(['created_at' => CarbonImmutable::now()->subHour()])->save();

        $tied = [$this->totpFactor($user, ['label' => 'first'])->id, $this->totpFactor($user, ['label' => 'second'])->id];

        sort($tied);

        $preferred->forceFill(['created_at' => CarbonImmutable::now()->addHours(2)])->save();

        $ids = array_map(static fn (FactorSummary $factor): string => $factor->id, $this->mfa()->offeredFactors(Callers::current()));

        self::assertSame([$preferred->id, $oldest->id, ...$tied, $newest->id], $ids);
    }

    /**
     * A pending factor, a type not enabled, a factor at the ceiling and one the
     * policy does not accept are left out; a temporarily locked factor stays.
     *
     * @return void
     */
    public function testWhatCannotSucceedIsLeftOut(): void
    {
        $this->enableApplication(['types' => ['totp', 'email'], 'first_factor' => ['method' => 'email', 'channel' => 'email']]);

        $user = $this->signedInPerson();

        $this->totpFactor($user, ['status' => 'pending', 'confirmed_at' => null]);
        $this->totpFactor($user, ['disabled_at' => CarbonImmutable::now()]);
        $this->factorOf($user, ['type' => 'sms', 'destination' => '+447700900123']);
        $this->emailFactor($user);

        $locked = $this->totpFactor($user, ['locked_until' => CarbonImmutable::now()->addHour()]);

        $offered = $this->mfa()->offeredFactors(Callers::current());

        self::assertCount(1, $offered);
        self::assertSame($locked->id, $offered[0]->id);
    }

    /**
     * A passkey is left out when passkeys are unavailable, its association is
     * missing or the gateway no longer lists its credential.
     *
     * @return void
     */
    public function testAPasskeyThatCannotTakePartIsLeftOut(): void
    {
        $gateway = $this->enablePasskeys();
        $user    = $this->signedInPerson();
        $factor  = $this->passkeyFactor($user);

        self::assertCount(1, $this->mfa()->offeredFactors(Callers::current()));

        $gateway->available = false;

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));

        $gateway->available  = true;
        $gateway->registered = [];

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));

        $gateway->registered = [self::CREDENTIAL];

        PasskeyAssociation::query()->where('factor_id', $factor->id)->delete();

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));
    }

    /**
     * A pending session must allow listing factors, and is offered its own.
     *
     * @return void
     */
    public function testAPendingSessionMustAllowListing(): void
    {
        $guarded = $this->signedInPerson();

        $this->totpFactor($guarded);

        $user   = $this->person('pending@example.test');
        $factor = $this->totpFactor($user);

        $this->pendingSession($user, actions: [PendingAction::VERIFY]);

        $refused = $this->mfa()->offeredFactors(Callers::current());

        $this->pendingSession($user);

        $offered = $this->mfa()->offeredFactors(Callers::current());

        self::assertSame([], $refused);

        self::assertCount(1, $offered);
        self::assertSame($factor->id, $offered[0]->id);
    }

    /**
     * Nobody served, and a first factor not known, are offered nothing.
     *
     * @return void
     */
    public function testNothingIsOfferedWithoutAFirstFactor(): void
    {
        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(null));

        $this->enableApplication(['first_factor' => null]);

        $user = $this->signedInPerson();

        $this->totpFactor($user);

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));
    }

    /**
     * An inactive identity can send and verify nothing, so it is offered
     * nothing.
     *
     * @return void
     */
    public function testAnInactiveIdentityIsOfferedNothing(): void
    {
        $this->totpFactor($this->person());

        $store    = $this->container()->make(ProofStore::class);
        $active   = new NonEloquentIdentity;
        $inactive = new NonEloquentIdentity(active: false);

        $this->actingAs($active);

        $store->begin($active, self::APPLICATION, self::SESSION);

        self::assertCount(1, $this->mfa()->offeredFactors(Callers::current()));

        $this->actingAs($inactive);

        $store->begin($inactive, self::APPLICATION, self::SESSION);

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));
    }

    /**
     * The bound active state resolver, not the identity, decides who is
     * inactive: an identity it finds inactive is offered nothing, and one it
     * finds active is offered its factors, whatever each says of itself.
     *
     * @return void
     */
    public function testAnIdentityTheBoundResolverFindsInactiveIsOfferedNothing(): void
    {
        $this->totpFactor($this->person());

        $this->container()->instance(ActiveStateResolver::class, new InvertedActiveState);

        $store    = $this->container()->make(ProofStore::class);
        $active   = new NonEloquentIdentity;
        $inactive = new NonEloquentIdentity(active: false);

        $this->actingAs($active);

        $store->begin($active, self::APPLICATION, self::SESSION);

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));

        $this->actingAs($inactive);

        $store->begin($inactive, self::APPLICATION, self::SESSION);

        self::assertCount(1, $this->mfa()->offeredFactors(Callers::current()));
    }

    /**
     * A pending session whose first factor no longer counts is offered nothing,
     * since sending and verifying would refuse it.
     *
     * @return void
     */
    public function testAPendingSessionsStaleFirstFactorIsOfferedNothing(): void
    {
        $user = $this->person();

        $this->totpFactor($user);
        $this->pendingSession($user);

        self::assertCount(1, $this->mfa()->offeredFactors(Callers::current()));

        VerificationGeneration::advance($user);

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));
    }

    /**
     * A summary holds no secret, no code and no full destination.
     *
     * @return void
     */
    public function testASummaryHoldsNoSecret(): void
    {
        $user = $this->signedInPerson();

        $this->emailFactor($user);
        $this->totpFactor($user);

        $encoded = (string) json_encode($this->mfa()->offeredFactors(Callers::current()));

        self::assertStringNotContainsString(self::ADDRESS, $encoded);
        self::assertStringContainsString('example.test', $encoded);
        self::assertStringNotContainsString('GEZDGNBVGY3TQOJQ', $encoded);
    }
}
