<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Tests for `SessionProofStore`: sign-ins begin and end, proofs are recorded
 * only for their identity's current sign-in, and every read fails closed on a
 * proof of another identity, application, sign-in or generation, or one made
 * in the future.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofStore::class)]
final class SessionProofStoreTest extends TestCase
{
    use BuildsProofs, RefreshDatabase;

    /** @var string The application the proofs are made on. */
    private const string APPLICATION = 'web';

    /** @var string The session id of the identity's sign-in. */
    private const string SIGN_IN = 'sign-in-1';

    /** @var \Illuminate\Session\Store The session the store keeps its records in. */
    private Store $session;

    /**
     * Start every test with an empty session and a frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->session = new Store('test', new ArraySessionHandler(10));

        CarbonImmutable::setTestNow('2026-11-01T10:00:00.000000+00:00');
    }

    /**
     * An identity with no sign-in has no current session and no proofs.
     *
     * @return void
     */
    public function testAnIdentityWithNoSignInHasNoProofs(): void
    {
        $store = $this->store();

        self::assertNull($store->currentSession($this->user()));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION));
    }

    /**
     * Beginning a sign-in names the session the identity's proofs are bound
     * to.
     *
     * @return void
     */
    public function testBeginNamesTheCurrentSession(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::SIGN_IN);

        self::assertSame(self::SIGN_IN, $store->currentSession($this->user()));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION));
    }

    /**
     * A sign-in is never named by a blank session id.
     *
     * @return void
     */
    public function testBeginRefusesABlankSessionId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The session id of a sign-in must not be blank.');

        $this->store()->begin($this->user(), ' ');
    }

    /**
     * A proof bound to the identity's current sign-in is recorded and read
     * back whole.
     *
     * @return void
     */
    public function testRecordsAProofOfTheCurrentSignIn(): void
    {
        $store = $this->store();
        $proof = $this->proofFor($this->user());

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($proof);

        self::assertSame([$proof->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION)));
    }

    /**
     * A proof bound to another sign-in of the identity is refused.
     *
     * @return void
     */
    public function testRefusesAProofOfAnotherSignIn(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::SIGN_IN);

        $this->expectException(ProofRefusedException::class);
        $this->expectExceptionMessage('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.');

        $store->record($this->proofFor($this->user(), ['session' => 'sign-in-2']));
    }

    /**
     * A proof of an identity with no sign-in is refused.
     *
     * @return void
     */
    public function testRefusesAProofWithoutASignIn(): void
    {
        $this->expectException(ProofRefusedException::class);

        $this->store()->record($this->proofFor($this->user()));
    }

    /**
     * Beginning a new sign-in forgets every proof of the one before, even
     * under the same session id.
     *
     * @return void
     */
    public function testBeginForgetsThePreviousSignInsProofs(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($this->proofFor($this->user()));
        $store->begin($this->user(), self::SIGN_IN);

        self::assertSame([], $store->proofs($this->user(), self::APPLICATION));
    }

    /**
     * The ways a stored proof fails to count for the identity's sign-in on
     * the application: another application, a time after now, a generation
     * the identity has not reached. An older generation is covered by the
     * generation bump below.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function nonCountingProofs(): iterable
    {
        yield 'another application' => [['application' => 'admin']];
        yield 'a time in the future' => [['provedAt' => CarbonImmutable::parse('2026-11-01T10:00:00.000001+00:00')]];
        yield 'a newer generation' => [['generation' => 1]];
    }

    /**
     * A recorded proof that does not count for the identity's sign-in on the
     * application is left out, while one that does is returned.
     *
     * @param  array<string, mixed>  $overrides
     * @return void
     */
    #[DataProvider('nonCountingProofs')]
    public function testFailsClosedOnAProofThatDoesNotCount(array $overrides): void
    {
        $store    = $this->store();
        $counting = $this->proofFor($this->user(), ['reference' => 'factor-2']);

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($this->proofFor($this->user(), $overrides));
        $store->record($counting);

        self::assertSame([$counting->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION)));
    }

    /**
     * A proof made exactly now counts.
     *
     * @return void
     */
    public function testAProofMadeNowCounts(): void
    {
        $store = $this->store();
        $proof = $this->proofFor($this->user(), ['provedAt' => CarbonImmutable::now()]);

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($proof);

        self::assertCount(1, $store->proofs($this->user(), self::APPLICATION));
    }

    /**
     * Advancing the identity's verification generation stops every proof of
     * its current sign-in made before counting, while one made under the new
     * generation counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGenerationBumpInvalidatesTheSignInsProofs(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($this->proofFor($this->user()));

        VerificationGeneration::advance($this->user());

        $fresh = $this->proofFor($this->user(), ['reference' => 'factor-2', 'generation' => 1]);

        $store->record($fresh);

        self::assertSame([$fresh->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION)));
    }

    /**
     * Another identity, whose type differs but whose key is the same, holds
     * its own sign-in and sees none of the first one's proofs.
     *
     * @return void
     */
    public function testAnotherIdentityTypeWithTheSameKeySeesNothing(): void
    {
        $store     = $this->store();
        $secondary = new SecondaryUser;

        $secondary->setAttribute('id', 7);

        $store->begin($this->user(), self::SIGN_IN);
        $store->begin($secondary, self::SIGN_IN);
        $store->record($this->proofFor($this->user()));

        self::assertSame([], $store->proofs($secondary, self::APPLICATION));
        self::assertCount(1, $store->proofs($this->user(), self::APPLICATION));
    }

    /**
     * A proof of another identity planted in the identity's record is never
     * returned for it.
     *
     * @return void
     */
    public function testFailsClosedOnAProofOfAnotherIdentityInItsRecord(): void
    {
        $planted = $this->proofFor($this->user(8));

        $this->plant([$planted->toArray()]);

        self::assertSame([], $this->store()->proofs($this->user(), self::APPLICATION));
    }

    /**
     * A stored entry that cannot be read back as a proof is skipped, and the
     * others still count.
     *
     * @return void
     */
    public function testSkipsAStoredEntryThatIsNotAProof(): void
    {
        $proof = $this->proofFor($this->user());

        $this->plant([['kind' => 'unknown'], 'not-an-array', $proof->toArray()]);

        self::assertSame([$proof->toArray()], self::serialized($this->store()->proofs($this->user(), self::APPLICATION)));
    }

    /**
     * A session holding something other than records is read as no sign-in.
     *
     * @return void
     */
    public function testReadsMalformedSessionDataAsNoSignIn(): void
    {
        $this->session->put(SessionProofStore::SESSION_KEY, 'not-records');

        self::assertNull($this->store()->currentSession($this->user()));

        $this->session->put(SessionProofStore::SESSION_KEY, [(new ProofOwner(TestUser::class, '7'))->slot() => ['session' => 42, 'proofs' => []]]);

        self::assertNull($this->store()->currentSession($this->user()));

        $this->session->put(SessionProofStore::SESSION_KEY, [(new ProofOwner(TestUser::class, '7'))->slot() => ['session' => self::SIGN_IN, 'proofs' => 'none']]);

        self::assertNull($this->store()->currentSession($this->user()));
        self::assertSame([], $this->store()->proofs($this->user(), self::APPLICATION));
    }

    /**
     * The proofs are returned oldest first, whatever order they were recorded
     * in.
     *
     * @return void
     */
    public function testReturnsTheProofsOldestFirst(): void
    {
        $store = $this->store();
        $newer = $this->proofFor($this->user(), ['provedAt' => CarbonImmutable::now()->subMinute(), 'reference' => 'factor-2']);
        $older = $this->proofFor($this->user(), ['provedAt' => CarbonImmutable::now()->subMinutes(5)]);

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($newer);
        $store->record($older);

        self::assertSame([$older->toArray(), $newer->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION)));
    }

    /**
     * Forgetting a factor stops its proofs counting and keeps the others and
     * the sign-in.
     *
     * @return void
     */
    public function testForgetFactorStopsCountingItsProofs(): void
    {
        $store = $this->store();
        $kept  = $this->proofFor($this->user(), ['reference' => 'factor-2']);

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($this->proofFor($this->user()));
        $store->record($kept);
        $store->forgetFactor($this->user(), 'factor-1');

        self::assertSame(self::SIGN_IN, $store->currentSession($this->user()));
        self::assertSame([$kept->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION)));
    }

    /**
     * Forgetting a factor of an identity with no sign-in begins none.
     *
     * @return void
     */
    public function testForgetFactorWithoutASignInBeginsNone(): void
    {
        $store = $this->store();

        $store->forgetFactor($this->user(), 'factor-1');

        self::assertNull($store->currentSession($this->user()));
        self::assertFalse($this->session->has(SessionProofStore::SESSION_KEY));
    }

    /**
     * Forgetting the identity ends its sign-in and leaves other identities'
     * alone.
     *
     * @return void
     */
    public function testForgetEndsTheSignInAndLeavesOthersAlone(): void
    {
        $store = $this->store();
        $other = $this->user(8);

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($this->proofFor($this->user()));
        $store->begin($other, 'sign-in-2');
        $store->record($this->proofFor($other, ['session' => 'sign-in-2']));

        $store->forget($this->user());

        self::assertNull($store->currentSession($this->user()));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION));
        self::assertSame('sign-in-2', $store->currentSession($other));
        self::assertCount(1, $store->proofs($other, self::APPLICATION));
    }

    /**
     * A sign-in keeps at most `LIMIT` proofs, forgetting the earliest recorded
     * but never the first factor.
     *
     * @return void
     */
    public function testKeepsAtMostTheLimitAndNeverTheFirstFactor(): void
    {
        $store = $this->store();
        $first = $this->firstFactorFor($this->user());

        $store->begin($this->user(), self::SIGN_IN);
        $store->record($first);

        for ($index = 1; $index <= SessionProofStore::LIMIT; $index++) {
            $store->record($this->proofFor($this->user(), ['reference' => 'factor-' . $index, 'provedAt' => CarbonImmutable::now()->subSeconds(SessionProofStore::LIMIT - $index)]));
        }

        $proofs = $store->proofs($this->user(), self::APPLICATION);

        self::assertCount(SessionProofStore::LIMIT, $proofs);
        self::assertSame(ProofKind::FIRST_FACTOR, $proofs[0]->kind);
        self::assertSame('factor-2', $proofs[1]->reference);
        self::assertSame('factor-' . SessionProofStore::LIMIT, $proofs[SessionProofStore::LIMIT - 1]->reference);
    }

    /**
     * A sign-in holding only first factors past the limit keeps them all
     * rather than looping.
     *
     * @return void
     */
    public function testKeepsFirstFactorsPastTheLimit(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::SIGN_IN);

        for ($index = 0; $index <= SessionProofStore::LIMIT; $index++) {
            $store->record($this->firstFactorFor($this->user()));
        }

        self::assertCount(SessionProofStore::LIMIT + 1, $store->proofs($this->user(), self::APPLICATION));
    }

    /**
     * An identity whose key cannot name a record is refused rather than
     * sharing one.
     *
     * @return void
     */
    public function testRefusesAnIdentityWhoseKeyCannotNameARecord(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);

        $this->store()->currentSession(new NonScalarIdentifierUser);
    }

    /**
     * Build the store over the test's session.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\SessionProofStore
     */
    private function store(): SessionProofStore
    {
        return new SessionProofStore($this->session);
    }

    /**
     * A test user with the given key, never saved.
     *
     * @param  int  $id
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(int $id = 7): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', $id);

        return $user;
    }

    /**
     * An additional factor proof of the identity on the application, bound to
     * its sign-in at generation 0 a minute ago, with any part overridden.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  array<string, mixed>  $overrides
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function proofFor(MultiFactorAuthenticatable $identity, array $overrides = []): Proof
    {
        $owner       = ProofOwner::of($identity);
        $application = $overrides['application'] ?? self::APPLICATION;
        $session     = $overrides['session']     ?? self::SIGN_IN;

        unset($overrides['application'], $overrides['session']);

        self::assertIsString($application);
        self::assertIsString($session);

        return self::proof([
            'provedAt'   => CarbonImmutable::now()->subMinute(),
            'binding'    => new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::STEP_UP),
            'generation' => 0,
            ...$overrides,
        ]);
    }

    /**
     * A first factor proof of the identity, made with a password at sign-in
     * ten minutes ago.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function firstFactorFor(MultiFactorAuthenticatable $identity): Proof
    {
        $owner = ProofOwner::of($identity);

        return self::proof([
            'kind'       => ProofKind::FIRST_FACTOR,
            'method'     => 'password',
            'channel'    => new Channel(ChannelKind::PASSWORD),
            'reference'  => null,
            'provedAt'   => CarbonImmutable::now()->subMinutes(10),
            'binding'    => new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SIGN_IN, Purpose::SIGN_IN),
            'generation' => 0,
        ]);
    }

    /**
     * Store the given entries directly as the test user's record for its
     * sign-in.
     *
     * @param  list<mixed>  $entries
     * @return void
     */
    private function plant(array $entries): void
    {
        $this->session->put(SessionProofStore::SESSION_KEY, [
            (new ProofOwner(TestUser::class, '7'))->slot() => ['session' => self::SIGN_IN, 'proofs' => $entries],
        ]);
    }

    /**
     * The proofs in their serialised form, for comparison.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<array<string, mixed>>
     */
    private static function serialized(array $proofs): array
    {
        return array_map(static fn (Proof $proof): array => $proof->toArray(), $proofs);
    }
}
