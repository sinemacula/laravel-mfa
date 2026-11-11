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
 * Every read fails closed on a proof of another identity, application, sign-in
 * or generation, or one made in the future.
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

    /** @var string Another application the identity signs in to. */
    private const string OTHER_APPLICATION = 'admin';

    /** @var string The session id of the identity's sign-in. */
    private const string SIGN_IN = 'sign-in-1';

    /** @var \Illuminate\Session\Store The session the store keeps its records in. */
    private Store $session;

    /**
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
     * No current session either.
     *
     * @return void
     */
    public function testAnIdentityWithNoSignInHasNoProofs(): void
    {
        $store = $this->store();

        self::assertNull($store->currentSession($this->user(), self::APPLICATION));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * @return void
     */
    public function testBeginNamesTheCurrentSession(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);

        self::assertSame(self::SIGN_IN, $store->currentSession($this->user(), self::APPLICATION));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * @return void
     */
    public function testBeginRefusesABlankSessionId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The session id of a sign-in must not be blank.');

        $this->store()->begin($this->user(), self::APPLICATION, ' ');
    }

    /**
     * Read back whole.
     *
     * @return void
     */
    public function testRecordsAProofOfTheCurrentSignIn(): void
    {
        $store = $this->store();
        $proof = $this->proofFor($this->user());

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $proof);

        self::assertSame([$proof->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * @return void
     */
    public function testRefusesAProofOfAnotherSignIn(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);

        $this->expectException(ProofRefusedException::class);
        $this->expectExceptionMessage('The proof is not bound to its identity\'s current sign-in, so it cannot be recorded.');

        $store->record($this->user(), $this->proofFor($this->user(), ['session' => 'sign-in-2']));
    }

    /**
     * Even when it names the identity's current sign-in; nothing changes.
     *
     * @return void
     */
    public function testRefusesAProofOfAnotherIdentity(): void
    {
        $store = $this->store();
        $kept  = $this->proofFor($this->user());

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->begin($this->user(8), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $kept);

        try {
            $store->record($this->user(), $this->proofFor($this->user(8)));

            self::fail('A proof of another identity must be refused.');
        } catch (ProofRefusedException $exception) {
            self::assertSame('The proof is not bound to the identity, so it cannot be recorded.', $exception->getMessage());
        }

        self::assertSame([$kept->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
        self::assertSame([], $store->proofs($this->user(8), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * Even though the current one holds proofs.
     *
     * @return void
     */
    public function testReadsNoProofsForASignInThatIsNotCurrent(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));

        self::assertCount(1, $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, 'sign-in-2'));

        $store->begin($this->user(), self::APPLICATION, 'sign-in-2');

        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * @return void
     */
    public function testRefusesAProofWithoutASignIn(): void
    {
        $this->expectException(ProofRefusedException::class);

        $this->store()->record($this->user(), $this->proofFor($this->user()));
    }

    /**
     * Even when it names the session id of the identity's sign-in on another.
     *
     * @return void
     */
    public function testRefusesAProofOfAnApplicationWithoutASignIn(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);

        $this->expectException(ProofRefusedException::class);

        $store->record($this->user(), $this->proofFor($this->user(), ['application' => self::OTHER_APPLICATION]));
    }

    /**
     * Each holds its own proofs; beginning or forgetting one leaves the other
     * alone.
     *
     * @return void
     */
    public function testSignInsOnApplicationsAreKeptApart(): void
    {
        $store = $this->store();
        $admin = $this->proofFor($this->user(), ['application' => self::OTHER_APPLICATION, 'session' => 'sign-in-2']);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->begin($this->user(), self::OTHER_APPLICATION, 'sign-in-2');
        $store->record($this->user(), $this->proofFor($this->user()));
        $store->record($this->user(), $admin);

        self::assertSame(self::SIGN_IN, $store->currentSession($this->user(), self::APPLICATION));
        self::assertSame('sign-in-2', $store->currentSession($this->user(), self::OTHER_APPLICATION));
        self::assertSame([$admin->toArray()], self::serialized($store->proofs($this->user(), self::OTHER_APPLICATION, 'sign-in-2')));

        $store->begin($this->user(), self::APPLICATION, 'sign-in-3');

        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, 'sign-in-3'));
        self::assertSame([$admin->toArray()], self::serialized($store->proofs($this->user(), self::OTHER_APPLICATION, 'sign-in-2')));

        $store->forget($this->user(), self::APPLICATION);

        self::assertNull($store->currentSession($this->user(), self::APPLICATION));
        self::assertSame('sign-in-2', $store->currentSession($this->user(), self::OTHER_APPLICATION));
        self::assertSame([$admin->toArray()], self::serialized($store->proofs($this->user(), self::OTHER_APPLICATION, 'sign-in-2')));

        $store->forget($this->user(), self::OTHER_APPLICATION);

        self::assertSame([], $this->session->get(SessionProofStore::SESSION_KEY));
    }

    /**
     * Even under the same session id.
     *
     * @return void
     */
    public function testBeginForgetsThePreviousSignInsProofs(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));
        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);

        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * A future time or an unreached generation; an older generation and another
     * application are covered by later tests.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function nonCountingProofs(): iterable
    {
        yield 'a time in the future' => [['provedAt' => CarbonImmutable::parse('2026-11-01T10:00:00.000001+00:00')]];
        yield 'a newer generation' => [['generation' => 1]];
    }

    /**
     * One that does count is still returned.
     *
     * @param  array<string, mixed>  $overrides
     * @return void
     */
    #[DataProvider('nonCountingProofs')]
    public function testFailsClosedOnAProofThatDoesNotCount(array $overrides): void
    {
        $store    = $this->store();
        $counting = $this->proofFor($this->user(), ['reference' => 'factor-2']);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user(), $overrides));
        $store->record($this->user(), $counting);

        self::assertSame([$counting->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * @return void
     */
    public function testAProofMadeNowCounts(): void
    {
        $store = $this->store();
        $proof = $this->proofFor($this->user(), ['provedAt' => CarbonImmutable::now()]);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $proof);

        self::assertCount(1, $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * A proof made under the new generation counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGenerationBumpInvalidatesTheSignInsProofs(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));

        VerificationGeneration::advance($this->user());

        $fresh = $this->proofFor($this->user(), ['reference' => 'factor-2', 'generation' => 1]);

        $store->record($this->user(), $fresh);

        self::assertSame([$fresh->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * It holds its own sign-in.
     *
     * @return void
     */
    public function testAnotherIdentityTypeWithTheSameKeySeesNothing(): void
    {
        $store     = $this->store();
        $secondary = new SecondaryUser;

        $secondary->setAttribute('id', 7);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->begin($secondary, self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));

        self::assertSame([], $store->proofs($secondary, self::APPLICATION, self::SIGN_IN));
        self::assertCount(1, $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * @return void
     */
    public function testFailsClosedOnAProofOfAnotherIdentityInItsRecord(): void
    {
        $planted = $this->proofFor($this->user(8));

        $this->plant([$planted->toArray()]);

        self::assertSame([], $this->store()->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * @return void
     */
    public function testFailsClosedOnAProofOfAnotherApplicationInItsRecord(): void
    {
        $planted = $this->proofFor($this->user(), ['application' => self::OTHER_APPLICATION]);

        $this->plant([$planted->toArray()]);

        self::assertSame([], $this->store()->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * The others still count.
     *
     * @return void
     */
    public function testSkipsAStoredEntryThatIsNotAProof(): void
    {
        $proof = $this->proofFor($this->user());

        $this->plant([['kind' => 'unknown'], 'not-an-array', $proof->toArray()]);

        self::assertSame([$proof->toArray()], self::serialized($this->store()->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * @return void
     */
    public function testReadsMalformedSessionDataAsNoSignIn(): void
    {
        $this->session->put(SessionProofStore::SESSION_KEY, 'not-records');

        self::assertNull($this->store()->currentSession($this->user(), self::APPLICATION));

        $slot = (new ProofOwner(TestUser::class, '7'))->slot();

        $this->session->put(SessionProofStore::SESSION_KEY, [$slot => 'not-records']);

        self::assertNull($this->store()->currentSession($this->user(), self::APPLICATION));

        $this->session->put(SessionProofStore::SESSION_KEY, [$slot => [self::APPLICATION => 'not-a-record']]);

        self::assertNull($this->store()->currentSession($this->user(), self::APPLICATION));

        $this->session->put(SessionProofStore::SESSION_KEY, [$slot => [self::APPLICATION => ['session' => 42, 'proofs' => []]]]);

        self::assertNull($this->store()->currentSession($this->user(), self::APPLICATION));

        $this->session->put(SessionProofStore::SESSION_KEY, [$slot => [self::APPLICATION => ['session' => self::SIGN_IN, 'proofs' => 'none']]]);

        self::assertNull($this->store()->currentSession($this->user(), self::APPLICATION));
        self::assertSame([], $this->store()->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
    }

    /**
     * Even though the object offers the record's session and proofs by key.
     *
     * @return void
     */
    public function testReadsARecordHeldAsAnObjectAsNoSignIn(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));

        $slot   = (new ProofOwner(TestUser::class, '7'))->slot();
        $record = $this->session->get(SessionProofStore::SESSION_KEY)[$slot][self::APPLICATION];

        self::assertIsArray($record);

        foreach ([new \ArrayObject($record), (object) $record] as $object) {
            $this->session->put(SessionProofStore::SESSION_KEY, [$slot => [self::APPLICATION => $object]]);

            self::assertNull($store->currentSession($this->user(), self::APPLICATION), $object::class);
            self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN), $object::class);
        }
    }

    /**
     * Whatever order they were recorded in.
     *
     * @return void
     */
    public function testReturnsTheProofsOldestFirst(): void
    {
        $store = $this->store();
        $newer = $this->proofFor($this->user(), ['provedAt' => CarbonImmutable::now()->subMinute(), 'reference' => 'factor-2']);
        $older = $this->proofFor($this->user(), ['provedAt' => CarbonImmutable::now()->subMinutes(5)]);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $newer);
        $store->record($this->user(), $older);

        self::assertSame([$older->toArray(), $newer->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * @return void
     */
    public function testReturnsProofsOfOneInstantInTheOrderRecorded(): void
    {
        $store   = $this->store();
        $instant = CarbonImmutable::now()->subMinute();
        $second  = $this->proofFor($this->user(), ['provedAt' => $instant, 'reference' => 'factor-2']);
        $first   = $this->proofFor($this->user(), ['provedAt' => $instant, 'reference' => 'factor-1']);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $second);
        $store->record($this->user(), $first);

        self::assertSame([$second->toArray(), $first->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * The other proofs and the sign-in are kept.
     *
     * @return void
     */
    public function testForgetFactorStopsCountingItsProofs(): void
    {
        $store = $this->store();
        $kept  = $this->proofFor($this->user(), ['reference' => 'factor-2']);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));
        $store->record($this->user(), $kept);
        $store->forgetFactor($this->user(), 'factor-1');

        self::assertSame(self::SIGN_IN, $store->currentSession($this->user(), self::APPLICATION));
        self::assertSame([$kept->toArray()], self::serialized($store->proofs($this->user(), self::APPLICATION, self::SIGN_IN)));
    }

    /**
     * @return void
     */
    public function testForgetFactorReachesEveryApplication(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->begin($this->user(), self::OTHER_APPLICATION, 'sign-in-2');
        $store->record($this->user(), $this->proofFor($this->user()));
        $store->record($this->user(), $this->proofFor($this->user(), ['application' => self::OTHER_APPLICATION, 'session' => 'sign-in-2']));
        $store->forgetFactor($this->user(), 'factor-1');

        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
        self::assertSame([], $store->proofs($this->user(), self::OTHER_APPLICATION, 'sign-in-2'));
        self::assertSame('sign-in-2', $store->currentSession($this->user(), self::OTHER_APPLICATION));
    }

    /**
     * The malformed record is left as it was.
     *
     * @return void
     */
    public function testForgetFactorSkipsAMalformedRecord(): void
    {
        $slot = (new ProofOwner(TestUser::class, '7'))->slot();

        $this->session->put(SessionProofStore::SESSION_KEY, [$slot => [self::OTHER_APPLICATION => 'not-a-record']]);

        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));
        $store->forgetFactor($this->user(), 'factor-1');

        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
        self::assertSame('not-a-record', $this->session->get(SessionProofStore::SESSION_KEY)[$slot][self::OTHER_APPLICATION]);
    }

    /**
     * @return void
     */
    public function testForgetFactorWithoutASignInBeginsNone(): void
    {
        $store = $this->store();

        $store->forgetFactor($this->user(), 'factor-1');

        self::assertNull($store->currentSession($this->user(), self::APPLICATION));
        self::assertFalse($this->session->has(SessionProofStore::SESSION_KEY));
    }

    /**
     * @return void
     */
    public function testForgetEndsTheSignInAndLeavesOthersAlone(): void
    {
        $store = $this->store();
        $other = $this->user(8);

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->proofFor($this->user()));
        $store->begin($other, self::APPLICATION, 'sign-in-2');
        $store->record($other, $this->proofFor($other, ['session' => 'sign-in-2']));

        $store->forget($this->user(), self::APPLICATION);

        self::assertNull($store->currentSession($this->user(), self::APPLICATION));
        self::assertSame([], $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));
        self::assertSame('sign-in-2', $store->currentSession($other, self::APPLICATION));
        self::assertCount(1, $store->proofs($other, self::APPLICATION, 'sign-in-2'));
    }

    /**
     * The earliest recorded goes first, but never the latest first factor.
     *
     * @return void
     */
    public function testKeepsAtMostTheLimitAndNeverTheFirstFactor(): void
    {
        $store = $this->store();
        $first = $this->firstFactorFor($this->user());

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $first);

        for ($index = 1; $index <= SessionProofStore::LIMIT; $index++) {
            $provedAt = CarbonImmutable::now()->subSeconds(SessionProofStore::LIMIT - $index);

            $store->record($this->user(), $this->proofFor($this->user(), ['reference' => 'factor-' . $index, 'provedAt' => $provedAt]));
        }

        $proofs = $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN);

        self::assertCount(SessionProofStore::LIMIT, $proofs);
        self::assertSame(ProofKind::FIRST_FACTOR, $proofs[0]->kind);
        self::assertSame('factor-2', $proofs[1]->reference);
        self::assertSame('factor-' . SessionProofStore::LIMIT, $proofs[SessionProofStore::LIMIT - 1]->reference);
    }

    /**
     * The earliest are forgotten and the latest kept, without crowding out an
     * additional proof.
     *
     * @return void
     */
    public function testFirstFactorsPastTheLimitKeepTheLimitAndTheAdditionalProofs(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);

        for ($index = 0; $index <= SessionProofStore::LIMIT; $index++) {
            $store->record($this->user(), $this->firstFactorFor($this->user(), 'password-' . $index));
        }

        self::assertCount(SessionProofStore::LIMIT, $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));

        $additional = $this->proofFor($this->user());

        $store->record($this->user(), $additional);

        $proofs  = $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN);
        $methods = array_map(static fn (Proof $proof): string => $proof->method, $proofs);

        self::assertCount(SessionProofStore::LIMIT, $proofs);
        self::assertContains('password-' . SessionProofStore::LIMIT, $methods);
        self::assertNotContains('password-0', $methods);
        self::assertNotContains('password-1', $methods);
        self::assertSame($additional->toArray(), $proofs[SessionProofStore::LIMIT - 1]->toArray());
    }

    /**
     * Each forgets the earliest proof other than the first factor.
     *
     * @return void
     */
    public function testAFullSignInKeepsTakingAdditionalProofs(): void
    {
        $store = $this->store();

        $store->begin($this->user(), self::APPLICATION, self::SIGN_IN);
        $store->record($this->user(), $this->firstFactorFor($this->user()));

        for ($index = 1; $index <= SessionProofStore::LIMIT + 5; $index++) {
            $store->record($this->user(), $this->proofFor($this->user(), ['reference' => 'factor-' . $index]));
        }

        $references = array_map(static fn (Proof $proof): ?string => $proof->reference, $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));

        self::assertCount(SessionProofStore::LIMIT, $references);
        self::assertContains(null, $references);
        self::assertContains('factor-' . (SessionProofStore::LIMIT + 5), $references);
        self::assertNotContains('factor-6', $references);
        self::assertContains('factor-7', $references);
    }

    /**
     * On the next proof, keeping the first factor wherever it sits.
     *
     * @return void
     */
    public function testARecordPastTheLimitIsBroughtBackWithinIt(): void
    {
        $entries = [$this->proofFor($this->user(), ['reference' => 'factor-0'])->toArray(), $this->firstFactorFor($this->user())->toArray()];

        for ($index = 1; $index <= SessionProofStore::LIMIT; $index++) {
            $entries[] = $this->proofFor($this->user(), ['reference' => 'factor-' . $index])->toArray();
        }

        $this->plant($entries);

        $store = $this->store();

        $store->record($this->user(), $this->proofFor($this->user(), ['reference' => 'factor-latest']));

        $references = array_map(static fn (Proof $proof): ?string => $proof->reference, $store->proofs($this->user(), self::APPLICATION, self::SIGN_IN));

        self::assertCount(SessionProofStore::LIMIT, $references);
        self::assertContains(null, $references);
        self::assertNotContains('factor-0', $references);
        self::assertNotContains('factor-2', $references);
        self::assertContains('factor-3', $references);
        self::assertContains('factor-latest', $references);
    }

    /**
     * Refused rather than sharing one.
     *
     * @return void
     */
    public function testRefusesAnIdentityWhoseKeyCannotNameARecord(): void
    {
        $this->expectException(UnsupportedIdentifierException::class);

        $this->store()->currentSession(new NonScalarIdentifierUser, self::APPLICATION);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\SessionProofStore
     */
    private function store(): SessionProofStore
    {
        return new SessionProofStore($this->session);
    }

    /**
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
     * Bound to the identity's sign-in at generation 0, made a minute ago.
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
     * Made at sign-in ten minutes ago.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $method
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function firstFactorFor(MultiFactorAuthenticatable $identity, string $method = 'password'): Proof
    {
        $owner = ProofOwner::of($identity);

        return self::proof([
            'kind'       => ProofKind::FIRST_FACTOR,
            'method'     => $method,
            'channel'    => new Channel(ChannelKind::PASSWORD),
            'reference'  => null,
            'provedAt'   => CarbonImmutable::now()->subMinutes(10),
            'binding'    => new ProofBinding($owner->type, $owner->key, self::APPLICATION, self::SIGN_IN, Purpose::SIGN_IN),
            'generation' => 0,
        ]);
    }

    /**
     * Writes the entries directly as the user's record on the application.
     *
     * @param  list<mixed>  $entries
     * @return void
     */
    private function plant(array $entries): void
    {
        $this->session->put(SessionProofStore::SESSION_KEY, [
            (new ProofOwner(TestUser::class, '7'))->slot() => [self::APPLICATION => ['session' => self::SIGN_IN, 'proofs' => $entries]],
        ]);
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<array<string, mixed>>
     */
    private static function serialized(array $proofs): array
    {
        return array_map(static fn (Proof $proof): array => $proof->toArray(), $proofs);
    }
}
