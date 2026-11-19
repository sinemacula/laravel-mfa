<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Assurance\NoSmsAfterPhoneCode;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\InvertedActiveState;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\RecoveryCodes\CountingHasher;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Offers are the identity's confirmed factors of an enabled type that can
 * succeed after its first factor, preferred first.
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

    /** @var string Signed in with. */
    private const string PHONE = '+447700900123';

    /** @var string */
    private const string OTHER_PHONE = '+447700900456';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The preferred factor first, then the oldest, then by id.
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

        self::assertSame([$preferred->id, $oldest->id, ...$tied, $newest->id], $this->offeredIds());
    }

    /**
     * Pending, type not enabled, at the ceiling or not accepted by the policy;
     * a temporarily locked factor stays.
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
     * Passkeys unavailable, its association missing, or its credential no
     * longer listed by the gateway.
     *
     * @return void
     */
    public function testAPasskeyThatCannotTakePartIsLeftOut(): void
    {
        $gateway = $this->enablePasskeys();
        $user    = $this->signedInPerson();
        $factor  = $this->passkeyFactor($user);

        self::assertCount(1, $this->mfa()->offeredFactors(Callers::current()));
        self::assertSame([self::APPLICATION], $gateway->listedFor);

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
     * It is offered its own.
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
     * Nobody served, or a first factor not known.
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
     * It can send and verify nothing.
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
     * The resolver, not the identity, decides who is inactive.
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
     * Sending and verifying would refuse it.
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
     * No secret, no code and no full destination.
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

    /**
     * A bound resolver's first factor whose channel is not known.
     *
     * @return void
     */
    public function testNothingIsOfferedOrAcceptedAfterAnUnknownFirstFactor(): void
    {
        $user   = $this->signedInPerson();
        $signIn = SignInProofs::of($user)->inSession(self::SESSION)->underGeneration(VerificationGeneration::current($user));

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver($signIn->firstFactorOn(Channel::unknown())));

        $factor = $this->totpFactor($user);
        $email  = $this->emailFactor($user);
        $code   = $this->recoveryCode($user);
        $hasher = new CountingHasher($this->container()->make(Hasher::class));

        $this->container()->instance(Hasher::class, $hasher);

        self::assertSame([], $this->mfa()->offeredFactors(Callers::current()));
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->sendCode(Callers::current(), $email->id)->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Callers::current(), Submission::recoveryCode($code))->reason);
        self::assertSame([], $this->mailbox->sent());
        self::assertSame(0, $hasher->checks());
        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(0, $this->identityRun($user));
        self::assertSame(10, $this->mfa()->recoveryCodeStatus(Callers::current())?->remaining);
    }

    /**
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\ChannelKind, string, string, string}>
     */
    public static function provideSignInDestinations(): iterable
    {
        yield 'a phone' => [ChannelKind::SMS, self::PHONE, self::PHONE, self::OTHER_PHONE];
        yield 'a mailbox in another case' => [ChannelKind::EMAIL, self::ADDRESS, 'Person@Example.TEST', 'other@example.test'];
    }

    /**
     * The destination signed in with is no independent factor; another one is.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  string  $signedInWith
     * @param  string  $same
     * @param  string  $other
     * @return void
     */
    #[DataProvider('provideSignInDestinations')]
    public function testAFactorOnTheSignInsDestinationIsNeitherOfferedNorSentTo(ChannelKind $kind, string $signedInWith, string $same, string $other): void
    {
        $this->enableApplication(['types' => ['sms', 'email']]);

        $phones   = FakeSmsSender::fake($this->container());
        $user     = $this->signedInWith(new Channel($kind, $signedInWith));
        $refused  = $this->factorOf($user, ['type' => $kind->value, 'destination' => $same]);
        $accepted = $this->factorOf($user, ['type' => $kind->value, 'destination' => $other]);

        self::assertSame([$accepted->id], $this->offeredIds());
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->sendCode(Callers::current(), $refused->id)->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Callers::current(), Submission::challenge($refused->id, 'any', '000000'))->reason);
        self::assertSame([], [...$phones->sent(), ...$this->mailbox->sent()]);

        $challenge = (string) $this->mfa()->sendCode(Callers::current(), $accepted->id)->challengeId;
        $code      = ($kind === ChannelKind::SMS ? $phones : $this->mailbox)->lastCodeTo($other);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::challenge($accepted->id, $challenge, (string) $code))->isVerified());
    }

    /**
     * The default would accept SMS to another phone.
     *
     * @return void
     */
    public function testAStricterBoundPolicyIsHonoured(): void
    {
        $this->enableApplication(['types' => ['totp', 'sms']]);
        $this->container()->bind(CombinationPolicy::class, NoSmsAfterPhoneCode::class);

        $phones = FakeSmsSender::fake($this->container());
        $user   = $this->signedInWith(new Channel(ChannelKind::SMS, self::PHONE));
        $sms    = $this->factorOf($user, ['type' => 'sms', 'destination' => self::OTHER_PHONE]);
        $totp   = $this->totpFactor($user);

        self::assertSame([$totp->id], $this->offeredIds());
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->sendCode(Callers::current(), $sms->id)->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Callers::current(), Submission::challenge($sms->id, 'any', '000000'))->reason);
        self::assertSame([], $phones->sent());
        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($totp->id, AuthenticatorApp::code($totp)))->isVerified());
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signedInWith(Channel $channel): TestUser
    {
        $user   = $this->signedInPerson();
        $signIn = SignInProofs::of($user)->inSession(self::SESSION)->underGeneration(VerificationGeneration::current($user));

        $this->container()->make(ProofStore::class)->record($user, $signIn->firstFactorOn($channel, 60));

        return $user;
    }

    /**
     * @return list<string>
     */
    private function offeredIds(): array
    {
        return array_map(static fn (FactorSummary $factor): string => $factor->id, $this->mfa()->offeredFactors(Callers::current()));
    }
}
