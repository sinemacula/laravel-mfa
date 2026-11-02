<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Factors\InMemoryFactor;
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
     * An assertion is requested with exactly the factor's credential, bound
     * to the person's sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsExactlyTheFactorsCredential(): void
    {
        $options = $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP);

        self::assertSame([[self::CREDENTIAL]], $this->gateway->requested);
        self::assertSame(self::SESSION, $options['session']);
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

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));

        $this->gateway->registered = [self::CREDENTIAL];

        PasskeyAssociation::query()->update(['credential_id' => self::OTHER_CREDENTIAL]);

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));

        PasskeyAssociation::query()->delete();

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));
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

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));

        $this->signInWithPasskey(self::CREDENTIAL);

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));
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

        self::assertSame(FailureReason::LOCKED, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));

        $this->passkey->update(['disabled_at' => null, 'status' => 'pending']);

        self::assertSame(FailureReason::NOT_CONFIRMED, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));

        $this->passkey->update(['status' => 'confirmed']);

        config()->set('mfa.applications.web.types', ['totp']);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));
    }

    /**
     * A verified assertion of the factor's credential is returned with what it
     * observed, and stamps the factor's last use.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReturnsWhatAVerifiedAssertionObserved(): void
    {
        $properties               = new ObservedProperties(userPresence: true, userVerification: true);
        $this->gateway->assertion = new PasskeyAssertion(self::CREDENTIAL, $properties);

        $assertion = $this->assertions()->verifyAssertion($this->passkey, Purpose::STEP_UP, ['id' => self::CREDENTIAL]);

        self::assertSame($properties, $assertion?->properties);
        self::assertSame([[self::CREDENTIAL]], $this->gateway->verified);
        self::assertNotNull(Factor::query()->findOrFail($this->passkey->id)->getLastUsedAt());
    }

    /**
     * An assertion the gateway verifies for another credential fails, and is
     * counted against the factor; so is one that does not verify.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAssertionOfAnotherCredentialFailsAndIsCounted(): void
    {
        $this->gateway->assertion = new PasskeyAssertion(self::OTHER_CREDENTIAL, new ObservedProperties(userPresence: true));

        self::assertNull($this->assertions()->verifyAssertion($this->passkey, Purpose::STEP_UP, ['id' => self::OTHER_CREDENTIAL]));
        self::assertNull($this->assertions()->verifyAssertion($this->passkey, Purpose::STEP_UP, []));
        self::assertSame(2, Factor::query()->findOrFail($this->passkey->id)->getConsecutiveFailures());
    }

    /**
     * A factor that keeps no state of its own is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAFactorThatKeepsNoState(): void
    {
        $this->expectException(UnsupportedFactorException::class);

        $this->assertions()->verifyAssertion(new InMemoryFactor(type: 'passkey'), Purpose::STEP_UP, ['id' => self::CREDENTIAL]);
    }

    /**
     * A pending session that does not allow verifying is served nothing; one
     * that does is served its own identity's factor, on its own session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testServesAPendingSessionOnlyWhenItAllowsVerifying(): void
    {
        $this->pending([PendingAction::LIST_FACTORS]);

        self::assertSame([], $this->assertions()->requestAssertion($this->passkey, Purpose::SIGN_IN));
        self::assertNull($this->assertions()->verifyAssertion($this->passkey, Purpose::SIGN_IN, ['id' => self::CREDENTIAL]));

        $this->pending([PendingAction::VERIFY]);

        self::assertSame('pending-1', $this->assertions()->requestAssertion($this->passkey, Purpose::SIGN_IN)['session']);
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

        self::assertSame(FailureReason::NOT_FOUND, $this->refusal(fn () => $this->assertions()->requestAssertion($this->passkey, Purpose::STEP_UP)));
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
            new PendingContext($this->user, self::APPLICATION, 'pending-1', $first, Requirement::none(), $actions),
        ));
    }

    /**
     * The reason the call was refused with.
     *
     * @param  \Closure(): mixed  $call
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    private function refusal(\Closure $call): FailureReason
    {
        try {
            $call();
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        self::fail('The call was expected to be refused.');
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
