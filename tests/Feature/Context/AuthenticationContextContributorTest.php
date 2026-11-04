<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * The keys the package contributes to the authentication context under `mfa`,
 * pinned exactly for each kind of session, read from its recorded proofs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationContextContributor::class)]
final class AuthenticationContextContributorTest extends TestCase
{
    use ArrangesVerification;

    /** @var array<string, mixed> The whole context of a caller the package does not serve. */
    private const array NEUTRAL = [
        'accepted'                      => false,
        'multifactor'                   => false,
        'factor_types'                  => [],
        'level'                         => 'unclassified',
        'phishing_resistant'            => false,
        'user_verification'             => false,
        'last_verification_age_seconds' => null,
        'has_confirmed_factor'          => false,
    ];

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
     * The contributor fills the `mfa` namespace.
     *
     * @return void
     */
    public function testItFillsTheMfaNamespace(): void
    {
        self::assertSame('mfa', AuthenticationContextContributor::NAMESPACE);
    }

    /**
     * A password and a TOTP code are multifactor at AAL2.
     *
     * @return void
     */
    public function testAPasswordAndTotp(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(90)]);

        self::assertSame([
            'accepted'                      => true,
            'multifactor'                   => true,
            'factor_types'                  => ['totp'],
            'level'                         => 'aal2',
            'phishing_resistant'            => false,
            'user_verification'             => false,
            'last_verification_age_seconds' => 90,
            'has_confirmed_factor'          => true,
        ], $this->context());
    }

    /**
     * `has_confirmed_factor` is a fact: an identity whose only factor's stored
     * status is none the package knows reports no confirmed factor, while the
     * requirement, which is conservative, still holds it to MFA.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACorruptStatusIsNoConfirmedFactorYetStillHeldToMfa(): void
    {
        $this->enableApplication(['requirement' => 'enrolled', 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        $holder = FactorHolder::query()->create(['email' => 'holder@example.test']);

        $this->actingAs($holder);
        $this->container()->make(ProofStore::class)->begin($holder, self::APPLICATION, self::SESSION);

        Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'status'               => 'CONFIRMED',
        ]);

        self::assertFalse($this->context()['has_confirmed_factor']);
        self::assertTrue($holder->isMfaEnabled());
        self::assertSame(
            ['additional_verification' => ['max_age' => null]],
            $this->container()->make(RequirementService::class)->requirementFor($holder, self::APPLICATION)->toArray(),
        );
    }

    /**
     * A password and an email code are accepted without being multifactor.
     *
     * @return void
     */
    public function testAPasswordAndEmail(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->email(45)]);

        self::assertSame([
            'accepted'                      => true,
            'multifactor'                   => false,
            'factor_types'                  => ['email'],
            'level'                         => 'aal1',
            'phishing_resistant'            => false,
            'user_verification'             => false,
            'last_verification_age_seconds' => 45,
            'has_confirmed_factor'          => false,
        ], $this->context());
    }

    /**
     * A recovery code counts as evidence: its type is named and its age read.
     *
     * @return void
     */
    public function testARecoveryCodeAlone(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, fn (SignInProofs $signIn): array => [$signIn->password(3600), $this->recoveryCodeProof($user, 120)]);

        self::assertSame([
            'accepted'                      => true,
            'multifactor'                   => true,
            'factor_types'                  => ['recovery_code'],
            'level'                         => 'aal2',
            'phishing_resistant'            => false,
            'user_verification'             => false,
            'last_verification_age_seconds' => 120,
            'has_confirmed_factor'          => false,
        ], $this->context());
    }

    /**
     * A passkey first factor that observed user verification meets the part on
     * its own, with no evidence to give an age.
     *
     * @return void
     */
    public function testAPasskeyFirstFactorAlone(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->passkey(true, 60)]);

        self::assertSame([
            'accepted'                      => true,
            'multifactor'                   => true,
            'factor_types'                  => [],
            'level'                         => 'aal2',
            'phishing_resistant'            => true,
            'user_verification'             => true,
            'last_verification_age_seconds' => null,
            'has_confirmed_factor'          => false,
        ], $this->context());
    }

    /**
     * A first factor on an unknown channel establishes nothing, so a further
     * proof after it is no evidence.
     *
     * @return void
     */
    public function testAFirstFactorOnAnUnknownChannel(): void
    {
        $user = $this->signedInPerson();

        $firstFactor = $this->firstFactorOn($user, new Channel(ChannelKind::UNKNOWN), new ObservedProperties(userVerification: true));

        $this->prove($user, static fn (SignInProofs $signIn): array => [$firstFactor, $signIn->totp(30)]);

        $this->totpFactor($user);

        self::assertSame([...self::NEUTRAL, 'has_confirmed_factor' => true], $this->context());
    }

    /**
     * A first factor that observed user verification counts for it only when it
     * supports a level.
     *
     * @return void
     */
    public function testAnUnclassifiedFirstFactorDoesNotCountForUserVerification(): void
    {
        $user = $this->signedInPerson();

        $firstFactor = $this->firstFactorOn($user, new Channel(ChannelKind::EXTERNAL_PROVIDER, 'provider-1'), new ObservedProperties(userVerification: true));

        $this->prove($user, static fn (): array => [$firstFactor]);

        self::assertFalse($this->context()['user_verification']);
        self::assertSame('unclassified', $this->context()['level']);
    }

    /**
     * A first factor that observed no user verification does not report it,
     * though it supports a level.
     *
     * @return void
     */
    public function testAFirstFactorThatDidNotVerifyTheUserDoesNotCount(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->passkey(false, 60)]);

        self::assertFalse($this->context()['user_verification']);
        self::assertSame('aal1', $this->context()['level']);
    }

    /**
     * Evidence that observed user verification counts for it, after a first
     * factor that did not.
     *
     * @return void
     */
    public function testEvidenceThatVerifiedTheUserCounts(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(90), $this->passkeyFactorProof($user, 30)]);

        $context = $this->context();

        self::assertTrue($context['user_verification']);
        self::assertSame(['totp', 'passkey'], $context['factor_types']);
        self::assertSame(30, $context['last_verification_age_seconds']);
    }

    /**
     * Each type is named once, oldest first, and the age is the newest
     * evidence's.
     *
     * @return void
     */
    public function testTypesAreUniqueOldestFirstAndTheAgeIsTheNewests(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->email(900), $signIn->email(600), $signIn->totp(30)]);

        $context = $this->context();

        self::assertSame(['email', 'totp'], $context['factor_types']);
        self::assertSame(30, $context['last_verification_age_seconds']);
    }

    /**
     * The first factor is found wherever the store holds it among the proofs,
     * such as behind an older proof that does not count.
     *
     * @return void
     */
    public function testTheFirstFactorIsFoundBehindAnOlderProof(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->totp(7200), $signIn->passkey(true, 3600)]);

        $context = $this->context();

        self::assertTrue($context['user_verification']);
        self::assertSame([], $context['factor_types']);
    }

    /**
     * A proof on the first factor's own channel is no evidence.
     *
     * @return void
     */
    public function testAProofOnASharedChannelIsNotEvidence(): void
    {
        $user = $this->signedInPerson();

        $firstFactor = $this->firstFactorOn($user, new Channel(ChannelKind::EMAIL, 'person@example.com'), ObservedProperties::none());

        $this->prove($user, static fn (SignInProofs $signIn): array => [$firstFactor, $signIn->email(30)]);

        $context = $this->context();

        self::assertSame([], $context['factor_types']);
        self::assertNull($context['last_verification_age_seconds']);
        self::assertFalse($context['accepted']);
    }

    /**
     * A reauthentication with the first factor is no evidence either.
     *
     * @return void
     */
    public function testAReauthenticationIsNotEvidence(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->reauthentication(10)]);

        $context = $this->context();

        self::assertSame([], $context['factor_types']);
        self::assertNull($context['last_verification_age_seconds']);
    }

    /**
     * With no first factor the store knows, or more than one, nothing is
     * evidence.
     *
     * @return void
     */
    public function testNotExactlyOneFirstFactorHasNoEvidence(): void
    {
        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(null));

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->totp(30)]);

        self::assertSame(self::NEUTRAL, $this->context());

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->passkey(true, 1800)]);

        self::assertSame(self::NEUTRAL, $this->context());
    }

    /**
     * The age is read against the clock.
     *
     * @return void
     */
    public function testTheAgeFollowsTheClock(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(90)]);

        self::assertSame(90, $this->context()['last_verification_age_seconds']);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(10)->addMilliseconds(500));

        self::assertSame(100, $this->context()['last_verification_age_seconds']);
    }

    /**
     * A guest has the neutral context.
     *
     * @return void
     */
    public function testAGuestIsNeutral(): void
    {
        self::assertSame(self::NEUTRAL, $this->context());
    }

    /**
     * A machine has the neutral context, whatever it reports.
     *
     * @return void
     */
    public function testAMachineIsNeutral(): void
    {
        $this->actingAs(new NonEloquentIdentity('robot-1', mfaEnabled: true, person: false));

        self::assertSame(self::NEUTRAL, $this->context());
    }

    /**
     * An identity that is not MFA-capable has the neutral context.
     *
     * @return void
     */
    public function testAnIdentityThatIsNotMfaCapableIsNeutral(): void
    {
        $this->actingAs(PlainUser::query()->create(['email' => 'plain@example.test']));

        self::assertSame(self::NEUTRAL, $this->context());
    }

    /**
     * An inactive identity has the neutral context, whatever it reports.
     *
     * @return void
     */
    public function testAnInactiveIdentityIsNeutral(): void
    {
        $this->actingAs(new NonEloquentIdentity('person-1', mfaEnabled: true, active: false));

        self::assertSame(self::NEUTRAL, $this->context());
    }

    /**
     * A pending session has the neutral context, also with an active one beside
     * it that has met everything: its enrolment information comes through the
     * pending flow.
     *
     * @return void
     */
    public function testAPendingSessionIsNeutral(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(90)]);

        self::assertTrue($this->context()['accepted']);

        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        self::assertSame(self::NEUTRAL, $this->context());
    }

    /**
     * One instance answers for whoever each request serves, so nothing is
     * shared between consecutive requests.
     *
     * @return void
     */
    public function testConsecutiveRequestsThroughOneInstanceShareNothing(): void
    {
        $instance = $this->container()->make(AuthenticationContextContributor::class);
        $proved   = $this->signedInPerson();
        $unproved = $this->person('other@example.test');

        $this->prove($proved, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(90)]);

        $this->container()->make(ProofStore::class)->begin($unproved, self::APPLICATION, 'sign-in-b');

        self::assertTrue($instance->contribute()['accepted']);

        $this->actingAs($unproved);

        self::assertFalse($instance->contribute()['accepted']);

        $this->actingAs($proved);

        self::assertTrue($instance->contribute()['accepted']);
    }

    /**
     * The facade reads the same keys.
     *
     * @return void
     */
    public function testTheFacadeReadsTheContext(): void
    {
        self::assertSame(self::NEUTRAL, Mfa::authenticationContext());
    }

    /**
     * A named sign-in's context is built from the proofs given, without the
     * request serving anyone.
     *
     * @return void
     */
    public function testANamedSignInFromTheProofsGiven(): void
    {
        $user = TestUser::query()->create(['email' => 'named@example.test']);

        $this->totpFactor($user);

        $signIn = SignInProofs::of($user)->inSession('named-sign-in');

        self::assertSame([
            'accepted'                      => true,
            'multifactor'                   => true,
            'factor_types'                  => ['totp'],
            'level'                         => 'aal2',
            'phishing_resistant'            => false,
            'user_verification'             => false,
            'last_verification_age_seconds' => 90,
            'has_confirmed_factor'          => true,
        ], $this->contributor()->contributeFor($user, self::APPLICATION, 'named-sign-in', $signIn->totp(90), $signIn->password(3600)));
    }

    /**
     * A named sign-in reads only the proofs that count for it: none of another
     * sign-in, another application or an older verification generation, and
     * none dated in the future.
     *
     * @return void
     */
    public function testANamedSignInReadsOnlyTheProofsThatCount(): void
    {
        $user = TestUser::query()->create(['email' => 'counting@example.test']);

        $this->totpFactor($user);

        VerificationGeneration::advance($user);

        $current = SignInProofs::of($user)->inSession('named-sign-in')->underGeneration(1);
        $older   = SignInProofs::of($user)->inSession('named-sign-in')->underGeneration(0);
        $other   = SignInProofs::of($user)->inSession('other-sign-in')->underGeneration(1);

        $context = $this->contributor()->contributeFor(
            $user,
            self::APPLICATION,
            'named-sign-in',
            $current->password(3600),
            $older->totp(10),
            $other->totp(20),
            $current->totp(-60),
            $current->totp(300),
        );

        self::assertTrue($context['accepted']);
        self::assertSame(300, $context['last_verification_age_seconds']);
        $elsewhere = $this->contributor()->contributeFor($user, 'other-application', 'named-sign-in', $current->password(3600), $current->totp(300));

        self::assertFalse($elsewhere['accepted']);
        self::assertSame([], $elsewhere['factor_types']);
    }

    /**
     * A named sign-in of a machine or an inactive identity has the neutral
     * context, whatever proofs are given.
     *
     * @return void
     */
    public function testANamedSignInOfAMachineOrAnInactiveIdentityIsNeutral(): void
    {
        $machine  = new NonEloquentIdentity('robot-1', mfaEnabled: true, person: false);
        $inactive = new NonEloquentIdentity('person-1', mfaEnabled: true, active: false);

        self::assertSame(self::NEUTRAL, $this->contributor()->contributeFor($machine, self::APPLICATION, 'named-sign-in'));
        self::assertSame(self::NEUTRAL, $this->contributor()->contributeFor($inactive, self::APPLICATION, 'named-sign-in'));
    }

    /**
     * The contributor under test.
     *
     * @return \SineMacula\Laravel\Mfa\Context\AuthenticationContextContributor
     */
    private function contributor(): AuthenticationContextContributor
    {
        return $this->container()->make(AuthenticationContextContributor::class);
    }

    /**
     * The context the contributor gives now.
     *
     * @return array<string, mixed>
     */
    private function context(): array
    {
        return $this->container()->make(AuthenticationContextContributor::class)->contribute();
    }

    /**
     * Begin the person's sign-in afresh and record the proofs on it.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return void
     */
    private function prove(TestUser $user, \Closure $proofs): void
    {
        $store  = $this->container()->make(ProofStore::class);
        $signIn = SignInProofs::of($user)->inSession(self::SESSION)->underGeneration(VerificationGeneration::current($user));

        $store->begin($user, self::APPLICATION, self::SESSION);

        foreach ($proofs($signIn) as $proof) {
            $store->record($proof);
        }
    }

    /**
     * A first factor of the person's on the channel, having observed the
     * properties, an hour ago.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function firstFactorOn(TestUser $user, Channel $channel, ObservedProperties $properties): Proof
    {
        return new Proof(ProofKind::FIRST_FACTOR, 'password', $channel, null, $properties, CarbonImmutable::now()->subHour(), $this->binding($user, Purpose::SIGN_IN), 0);
    }

    /**
     * A recovery code the person redeemed.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function recoveryCodeProof(TestUser $user, int $secondsAgo): Proof
    {
        $provedAt = CarbonImmutable::now()->subSeconds($secondsAgo);

        return new Proof(ProofKind::RECOVERY_CODE, 'recovery_code', null, null, ObservedProperties::none(), $provedAt, $this->binding($user, Purpose::SIGN_IN), 0);
    }

    /**
     * A passkey factor's assertion that observed user verification.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function passkeyFactorProof(TestUser $user, int $secondsAgo): Proof
    {
        $properties = new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true);
        $provedAt   = CarbonImmutable::now()->subSeconds($secondsAgo);
        $channel    = new Channel(ChannelKind::PASSKEY, 'credential-1');

        return new Proof(ProofKind::ADDITIONAL_FACTOR, 'passkey', $channel, 'factor-passkey', $properties, $provedAt, $this->binding($user, Purpose::STEP_UP), 0);
    }

    /**
     * What a proof of the person's on the sign-in is bound to.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private function binding(TestUser $user, Purpose $purpose): ProofBinding
    {
        $owner = ProofOwner::of($user);

        return new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SESSION, $purpose);
    }
}
