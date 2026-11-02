<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\AssertionRequest;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use Tests\Fixtures\Assurance\RefusingCombinationPolicy;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\Fixtures\Passkeys\FakePasskeyGateway;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `PasskeyAssertions`: a ceremony for a passkey factor is allowed
 * exactly its associated credential, only while the gateway lists it, the
 * factor is usable and the combination policy accepts it after the session's
 * first factor; a verified assertion naming another credential fails, and a
 * failed one counts against the factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(AssertionRequest::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(PasskeyAssociations::class)]
final class PasskeyAssertionsTest extends TestCase
{
    use ArrangesPasskeys;

    /** @var \Tests\Fixtures\Passkeys\FakePasskeyGateway The gateway. */
    private FakePasskeyGateway $gateway;

    /** @var \Tests\Fixtures\Identities\TestUser The person signed in. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's passkey factor. */
    private Factor $passkey;

    /**
     * Sign a person in with a passkey factor the gateway lists.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->gateway = $this->enablePasskeys(registered: [self::CREDENTIAL, self::OTHER_CREDENTIAL]);
        $this->user    = $this->signedInPerson();
        $this->passkey = $this->confirmedFactor($this->user, 'passkey', self::CREDENTIAL);
    }

    /**
     * An assertion is requested with exactly the factor's credential, bound to
     * the person's sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsExactlyTheFactorsCredential(): void
    {
        $request = $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP);

        self::assertTrue($request->hasStarted());
        self::assertNull($request->reason);
        self::assertSame([[self::CREDENTIAL]], $this->gateway->requested);
        self::assertSame(self::SESSION, $request->options['session']);
    }

    /**
     * A credential the gateway no longer lists, one not associated, and one
     * whose association names another credential are refused, so no ceremony
     * ever starts with an empty or wider allowlist.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesACredentialThatIsNotTheFactorsOwn(): void
    {
        $this->gateway->registered = [self::OTHER_CREDENTIAL];

        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);

        $this->gateway->registered = [self::CREDENTIAL];

        PasskeyAssociation::query()->update(['credential_id' => self::OTHER_CREDENTIAL]);

        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);

        PasskeyAssociation::query()->delete();

        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);
        self::assertSame([], $this->gateway->requested);
    }

    /**
     * The passkey that started the sign-in is never its second factor, nor is
     * any passkey after a first factor that names no credential.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesTheFirstFactorsPasskey(): void
    {
        $this->enablePasskeys(['first_factor' => ['method' => 'passkey', 'channel' => 'passkey']], [self::CREDENTIAL]);

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);

        $this->signInWithPasskey(self::CREDENTIAL);

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);
    }

    /**
     * A pending or disabled factor, and one of a type the application does not
     * enable, are refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAFactorThatIsNotUsable(): void
    {
        $this->passkey->update(['disabled_at' => CarbonImmutable::now()]);

        self::assertSame(FailureReason::LOCKED, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);

        $this->passkey->update(['disabled_at' => null, 'status' => 'pending']);

        self::assertSame(FailureReason::NOT_CONFIRMED, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);

        $this->passkey->update(['status' => 'confirmed']);

        config()->set('mfa.applications.web.types', ['totp']);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);
    }

    /**
     * The options of a factor found earlier are still held to its state: a
     * pending one and one of a type the application no longer enables are
     * refused, as the package's own refusals.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOptionsRefuseAFactorNoLongerUsable(): void
    {
        $binding = $this->bindingOf($this->user, Purpose::STEP_UP);

        config()->set('mfa.applications.web.types', ['totp']);

        $this->assertOptionsRefused(FailureReason::TYPE_NOT_ENABLED, $binding);

        config()->set('mfa.applications.web.types', ['totp', 'passkey']);

        $this->passkey->update(['status' => 'pending']);

        $this->assertOptionsRefused(FailureReason::NOT_CONFIRMED, $binding);
    }

    /**
     * A verified assertion of the factor's credential is returned with what it
     * observed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReturnsWhatAVerifiedAssertionObserved(): void
    {
        $properties               = new ObservedProperties(userPresence: true, userVerification: true);
        $this->gateway->assertion = new PasskeyAssertion(self::CREDENTIAL, $properties, 'challenge-1');

        $assertion = $this->assertions()->check($this->user, $this->passkey, $this->bindingOf($this->user, Purpose::STEP_UP), ['id' => self::CREDENTIAL]);

        self::assertInstanceOf(PasskeyAssertion::class, $assertion);
        self::assertSame($properties, $assertion->properties);
        self::assertSame('challenge-1', $assertion->challengeId);
        self::assertSame([[self::CREDENTIAL]], $this->gateway->verified);
    }

    /**
     * An assertion the gateway verifies for another credential fails as an
     * invalid code, and why the gateway did not verify one is passed on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionOfAnotherCredentialFails(): void
    {
        $binding = $this->bindingOf($this->user, Purpose::STEP_UP);

        $this->gateway->assertion = new PasskeyAssertion(self::OTHER_CREDENTIAL, new ObservedProperties(userPresence: true));

        self::assertSame(FailureReason::INVALID_CODE, $this->assertions()->check($this->user, $this->passkey, $binding, ['id' => self::OTHER_CREDENTIAL]));

        $this->gateway->assertion = FailureReason::EXPIRED;

        self::assertSame(FailureReason::EXPIRED, $this->assertions()->check($this->user, $this->passkey, $binding, ['id' => self::CREDENTIAL]));
    }

    /**
     * A pending session that does not allow verifying is refused as not found;
     * one that does is served its own identity's factor, on its own session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testServesAPendingSessionOnlyWhenItAllowsVerifying(): void
    {
        $this->pending([PendingAction::LIST_FACTORS]);

        $refused = $this->requests()->requestAssertion($this->passkey->id, Purpose::SIGN_IN);

        self::assertFalse($refused->hasStarted());
        self::assertSame(FailureReason::NOT_FOUND, $refused->reason);
        self::assertSame([], $refused->options);

        $this->pending([PendingAction::VERIFY]);

        self::assertSame('pending-1', $this->requests()->requestAssertion($this->passkey->id, Purpose::SIGN_IN)->options['session']);
    }

    /**
     * A purpose a ceremony is not made for is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAPurposeNotOfACeremony(): void
    {
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->requests()->requestAssertion($this->passkey->id, Purpose::ENROLLMENT)->reason);
        self::assertSame([], $this->gateway->requested);
    }

    /**
     * Without a sign-in to bind the ceremony to, it is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesWithoutASignIn(): void
    {
        $this->container()->make(ProofStore::class)->forget($this->user, self::APPLICATION);

        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);
    }

    /**
     * Nobody served is refused as not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNobodyServedIsNotFound(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver);

        Auth::logout();

        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);
        self::assertSame([], $this->gateway->requested);
    }

    /**
     * The guard's own reasons are answers: a factor that is not the identity's,
     * and an inactive identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsReasonsAreAnswers(): void
    {
        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion('01JUNKNOWNFACTOR0000000000', Purpose::STEP_UP)->reason);

        $identity = new NonEloquentIdentity('inactive', active: false);
        $first    = SignInProofs::of($identity)->inSession('pending-1')->password();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($identity, self::APPLICATION, 'pending-1', $first, Requirement::none(), [PendingAction::VERIFY], CarbonImmutable::now()->addMinutes(10)),
        ));

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->requests()->requestAssertion($this->passkey->id, Purpose::SIGN_IN)->reason);
    }

    /**
     * A gateway's own refusal stays an exception, wherever it is asked: it is
     * the seam's to report, and is never read as the package deciding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGatewaysOwnRefusalPropagates(): void
    {
        $this->gateway->requestRefusal = new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The gateway refused.');

        $this->assertPropagates($this->gateway->requestRefusal);
    }

    /**
     * A gateway that fails with anything else propagates too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGatewayFailurePropagates(): void
    {
        $this->gateway->requestRefusal = new \RuntimeException('The gateway is down.');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The gateway is down.');

        $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP);
    }

    /**
     * A combination policy's own refusal stays an exception too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACombinationPolicysOwnRefusalPropagates(): void
    {
        $this->container()->instance(CombinationPolicy::class, new RefusingCombinationPolicy($this->container()->make(CombinationPolicy::class), 1));

        $this->assertPropagates();
    }

    /**
     * A subject type resolver that throws propagates, and one that answers no
     * is a refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSubjectTypeResolverDecidesOrPropagates(): void
    {
        $resolver = \Mockery::mock(SubjectTypeResolver::class);

        $resolver->shouldReceive('isPerson')->once()->andReturnFalse();
        $resolver->shouldReceive('isPerson')->once()->andThrow(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The resolver refused.'));

        $this->container()->instance(SubjectTypeResolver::class, $resolver);

        self::assertSame(FailureReason::NOT_FOUND, $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP)->reason);

        $this->assertPropagates();

        \Mockery::close();
    }

    /**
     * Asking for the factor's options is refused for the reason, by the
     * package.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Throwable
     */
    private function assertOptionsRefused(FailureReason $reason, ProofBinding $binding): void
    {
        try {
            $this->assertions()->options($this->user, $this->passkey, $binding);

            self::fail('The options must be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertTrue($exception->byPackage);
            self::assertSame($reason, $exception->reason);
        }
    }

    /**
     * Requesting an assertion throws a seam's refusal, unmarked.
     *
     * @param  ?\Throwable  $expected
     * @return void
     *
     * @throws \Throwable
     */
    private function assertPropagates(?\Throwable $expected = null): void
    {
        try {
            $this->requests()->requestAssertion($this->passkey->id, Purpose::STEP_UP);

            self::fail('A seam\'s refusal must propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertFalse($exception->byPackage);

            if ($expected !== null) {
                self::assertSame($expected, $exception);
            }
        }
    }

    /**
     * Record that the person signed in with the passkey given.
     *
     * @param  string  $credential
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signInWithPasskey(string $credential): void
    {
        $first = new Proof(
            kind      : ProofKind::FIRST_FACTOR,
            method    : 'passkey',
            channel   : new Channel(ChannelKind::PASSKEY, $credential),
            reference : null,
            properties: new ObservedProperties(userPresence: true),
            provedAt  : CarbonImmutable::now(),
            binding   : $this->bindingOf($this->user, Purpose::SIGN_IN),
            generation: 0,
        );

        $this->container()->make(ProofStore::class)->record($first);
    }

    /**
     * Make every request carry a pending session of the person's allowing the
     * actions.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @return void
     */
    private function pending(array $actions): void
    {
        $first = SignInProofs::of($this->user)->inSession('pending-1')->password();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($this->user, self::APPLICATION, 'pending-1', $first, Requirement::none(), $actions, CarbonImmutable::now()->addMinutes(10)),
        ));
    }

    /**
     * The requests under test.
     *
     * @return \SineMacula\Laravel\Mfa\Verification\ChallengeRequests
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requests(): ChallengeRequests
    {
        return $this->container()->make(ChallengeRequests::class);
    }

    /**
     * The assertions under test.
     *
     * @return \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertions(): PasskeyAssertions
    {
        return $this->container()->make(PasskeyAssertions::class);
    }
}
