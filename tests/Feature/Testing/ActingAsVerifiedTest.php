<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\Concerns\InteractsWithMfa;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use SineMacula\Laravel\Mfa\Testing\ProofStoreRecorder;
use SineMacula\Laravel\Mfa\Testing\VerifiedSignIn;
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Requirements\UnacceptingCombinationPolicy;
use Tests\Fixtures\Seams\LayerWrittenProofStore;
use Tests\Fixtures\Testing\LayerRecorder;
use Tests\Fixtures\Testing\LeveledCombinationPolicy;
use Tests\Fixtures\Testing\PendingLayerRecorder;
use Tests\Fixtures\Testing\RecordingGuard;
use Tests\Fixtures\Testing\RetainingProofStore;
use Tests\TestCase;

/**
 * Acting as an identity verified at a given time and level, through the real
 * `web` group and `mfa:` routes: what each level reaches, what the time does,
 * what is refused and leaves nothing changed, and what the fixture does not do.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerifiedSignIn::class)]
#[CoversClass(ProofStoreRecorder::class)]
#[CoversTrait(InteractsWithMfa::class)]
final class ActingAsVerifiedTest extends TestCase
{
    use InteractsWithMfa;

    /** @var string The operation the freshness route names. */
    private const string OPERATION = 'billing.close_books';

    /** @var int The operation's maximum age, in seconds. */
    private const int MAX_AGE = 300;

    /** @var string The application a second guard acts for. */
    private const string OTHER = 'admin';

    /**
     * Freeze the clock, and bound the operation on the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-01 12:00:00');

        config()->set('mfa.applications.web', ['types' => ['totp'], 'requirement' => 'never', 'freshness' => [self::OPERATION => self::MAX_AGE]]);
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
     * Each level reaches the routes at or below it and is refused above it.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: int, 2: int}>
     */
    public static function levels(): iterable
    {
        yield 'AAL1 meets AAL1 and not AAL2' => [AssuranceLevel::AAL1, 200, 401];
        yield 'AAL2 meets both' => [AssuranceLevel::AAL2, 200, 200];
    }

    /**
     * Each level, through the real routes.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  int  $aal1
     * @param  int  $aal2
     * @return void
     */
    #[DataProvider('levels')]
    public function testEachLevelReachesTheRoutesAtOrBelowIt(AssuranceLevel $level, int $aal1, int $aal2): void
    {
        $this->actingAsVerified($this->person(), $level);

        $this->getJson('verified/aal1')->assertStatus($aal1);
        $this->getJson('verified/aal2')->assertStatus($aal2);
    }

    /**
     * It returns the test, so a request can follow, as `actingAs()` does.
     *
     * @return void
     */
    public function testItReturnsTheTest(): void
    {
        self::assertSame($this, $this->actingAsVerified($this->person()));
    }

    /**
     * It acts as the identity, on the guard it names or the default, with a
     * model no longer counting as just created.
     *
     * @return void
     */
    public function testItActsAsTheIdentity(): void
    {
        $user = $this->person();

        self::assertTrue($user->wasRecentlyCreated);

        $this->actingAsVerified($user);

        $this->assertAuthenticatedAs($user);
        self::assertFalse($user->wasRecentlyCreated);

        $this->getJson('verified/level-free')->assertOk();
    }

    /**
     * AAL1 is an accepted further proof, not the password alone: an application
     * that always asks for additional verification lets it through.
     *
     * @return void
     */
    public function testAal1MeetsAdditionalVerification(): void
    {
        config()->set('mfa.applications.web.requirement', 'always');

        $user = $this->person();

        $this->actingAs($user);

        $this->getJson('verified/level-free')->assertUnauthorized();

        $this->actingAsVerified($user, AssuranceLevel::AAL1);

        $proofs = $this->heldBy($user, 'web');

        self::assertCount(2, $proofs);
        self::assertSame(ProofKind::FIRST_FACTOR, $proofs[0]->kind);
        self::assertSame('password', $proofs[0]->method);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[1]->kind);
        self::assertSame('email', $proofs[1]->method);
        self::assertSame(Purpose::SIGN_IN, $proofs[1]->binding->purpose);

        $this->getJson('verified/level-free')->assertOk();
    }

    /**
     * The further proof of each level is what that level is made of, so a
     * custom policy judges real evidence: TOTP at AAL2, and at AAL3 a passkey
     * observing presence, verification, phishing resistance and hardware.
     *
     * @return void
     */
    public function testTheFurtherProofIsWhatTheLevelIsMadeOf(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user);

        $totp = $this->heldBy($user, 'web')[1];

        self::assertSame('totp', $totp->method);
        self::assertNull($totp->properties->userVerification);

        $this->container()->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $this->actingAsVerified($user, AssuranceLevel::AAL3);

        $passkey = $this->heldBy($user, 'web')[1];

        self::assertSame('passkey', $passkey->method);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $passkey->kind);
        self::assertTrue($passkey->properties->userPresence);
        self::assertTrue($passkey->properties->userVerification);
        self::assertTrue($passkey->properties->phishingResistance);
        self::assertSame(KeyProtection::HARDWARE, $passkey->properties->keyProtection);
    }

    /**
     * An old time fails an operation's freshness, and a recent one passes.
     *
     * @return void
     */
    public function testTheTimeDecidesAnOperationsFreshness(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user, at: CarbonImmutable::now()->subSeconds(self::MAX_AGE + 1));

        $this->getJson('verified/operation')->assertUnauthorized();

        $this->actingAsVerified($user, at: CarbonImmutable::now()->subSeconds(self::MAX_AGE));

        $this->getJson('verified/operation')->assertOk();
    }

    /**
     * Any `DateTimeInterface` is taken as the time, and both proofs carry it.
     *
     * @return void
     */
    public function testBothProofsCarryTheTime(): void
    {
        $user = $this->person();
        $at   = new \DateTimeImmutable('2026-11-01 11:50:00', new \DateTimeZone('UTC'));

        $this->actingAsVerified($user, at: $at);

        foreach ($this->heldBy($user, 'web') as $proof) {
            self::assertSame($at->getTimestamp(), $proof->provedAt->getTimestamp());
        }
    }

    /**
     * Left out, the time is now.
     *
     * @return void
     */
    public function testTheTimeDefaultsToNow(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user);

        foreach ($this->heldBy($user, 'web') as $proof) {
            self::assertTrue($proof->provedAt->equalTo(CarbonImmutable::now()));
        }
    }

    /**
     * The arguments that cannot be honoured.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\AssuranceLevel, 1: string, 2: string}>
     */
    public static function refusedArguments(): iterable
    {
        yield 'unclassified' => [AssuranceLevel::UNCLASSIFIED, '2026-11-01 11:00:00', 'level'];
        yield 'the future' => [AssuranceLevel::AAL2, '2026-11-01 12:00:01', 'future'];
    }

    /**
     * An argument that cannot be honoured is refused with nothing changed: the
     * guard, its default and the store are as they were.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  string  $at
     * @param  string  $mentions
     * @return void
     */
    #[DataProvider('refusedArguments')]
    public function testARefusedArgumentChangesNothing(AssuranceLevel $level, string $at, string $mentions): void
    {
        $person = $this->person();
        $other  = $this->person('other@example.test');

        $this->actingAsVerified($person);

        $held = $this->heldBy($person, 'web');

        try {
            $this->actingAsVerified($other, $level, CarbonImmutable::parse($at), 'secondary');

            self::fail('The arguments must be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString($mentions, $exception->getMessage());
        }

        self::assertSame('web', Auth::getDefaultDriver());
        $this->assertAuthenticatedAs($person);
        self::assertFalse(Auth::guard('secondary')->hasUser());
        self::assertEquals($held, $this->heldBy($person, 'web'));
        self::assertSame([], $this->heldBy($other, 'secondary'));
    }

    /**
     * The present moment is not the future.
     *
     * @return void
     */
    public function testTheCurrentTimeIsAccepted(): void
    {
        $this->actingAsVerified($this->person(), at: CarbonImmutable::now());

        $this->getJson('verified/aal2')->assertOk();
    }

    /**
     * Under the default policy, which caps at AAL2, AAL3 fails loudly naming
     * all three facts.
     *
     * @return void
     */
    public function testAal3UnderTheDefaultPolicyFailsNamingWhatItReached(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal3 with additional verification; reached aal2; unmet: minimum_level.');

        $this->actingAsVerified($this->person(), AssuranceLevel::AAL3);
    }

    /**
     * A custom policy that rates the evidence AAL3 succeeds.
     *
     * @return void
     */
    public function testAal3UnderACustomPolicySucceeds(): void
    {
        $this->container()->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $this->actingAsVerified($this->person(), AssuranceLevel::AAL3);

        $this->getJson('verified/aal3')->assertOk();
    }

    /**
     * Asking for less than the evidence reaches fails rather than handing the
     * test a stronger session than it asked for: exactly the level, not at
     * least it.
     *
     * @return void
     */
    public function testALevelAboveTheOneRequestedFails(): void
    {
        $this->container()->instance(CombinationPolicy::class, new LeveledCombinationPolicy);

        $user  = $this->person();
        $store = new RetainingProofStore('kept');

        $this->container()->instance(ProofStore::class, $store);

        $store->record($user, $this->hardwarePasskeyFirstFactor($user));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal2 with additional verification; reached aal3; unmet: none.');

        $this->actingAsVerified($user);
    }

    /**
     * A policy that rejects the further proof fails naming additional
     * verification, though the level alone reads AAL1 from the password.
     *
     * @return void
     */
    public function testAPolicyRejectingTheFurtherProofFailsNamingIt(): void
    {
        $this->container()->instance(CombinationPolicy::class, new UnacceptingCombinationPolicy(VerifiedSignIn::EMAIL_REFERENCE));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal1 with additional verification; reached aal1; unmet: additional_verification.');

        $this->actingAsVerified($this->person(), AssuranceLevel::AAL1);
    }

    /**
     * The acting survives a second request through the kernel.
     *
     * @return void
     */
    public function testASecondRequestStillCounts(): void
    {
        $this->actingAsVerified($this->person());

        $this->getJson('verified/aal2')->assertOk();
        $this->getJson('verified/aal2')->assertOk();
    }

    /**
     * Acting again replaces the first: a lower level is no longer the higher
     * one.
     *
     * @return void
     */
    public function testActingAgainReplacesTheFirst(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user);
        $this->getJson('verified/aal2')->assertOk();

        $this->actingAsVerified($user, AssuranceLevel::AAL1);
        $this->getJson('verified/aal2')->assertUnauthorized();

        self::assertCount(2, $this->heldBy($user, 'web'));
    }

    /**
     * Two guards are kept apart: the proofs go where each names, and the last
     * guard acted on is the default.
     *
     * @return void
     */
    public function testTwoGuardsAreKeptApart(): void
    {
        $user  = $this->person();
        $other = $this->secondaryPerson();

        $this->actingAsVerified($other, guard: 'secondary');

        self::assertSame('secondary', Auth::getDefaultDriver());
        $this->assertAuthenticatedAs($other, 'secondary');
        $this->assertAuthenticatedAs($other);

        $this->actingAsVerified($user, AssuranceLevel::AAL1, guard: 'web');

        self::assertSame('web', Auth::getDefaultDriver());
        $this->assertAuthenticatedAs($user);

        self::assertSame('email', $this->heldBy($user, 'web')[1]->method);
        self::assertSame('totp', $this->heldBy($other, 'secondary')[1]->method);
        self::assertSame([], $this->heldBy($user, 'secondary'));
    }

    /**
     * Two applications are kept apart: the proofs go to the one named, leaving
     * the other's alone, and it does not choose what the next request resolves.
     *
     * @return void
     */
    public function testTwoApplicationsAreKeptApart(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user, application: self::OTHER);

        self::assertCount(2, $this->heldBy($user, self::OTHER));
        self::assertSame([], $this->heldBy($user, 'web'));

        $this->getJson('verified/aal2')->assertUnauthorized();

        $this->actingAsVerified($user, AssuranceLevel::AAL1);

        self::assertSame('totp', $this->heldBy($user, self::OTHER)[1]->method);
        self::assertSame('email', $this->heldBy($user, 'web')[1]->method);
    }

    /**
     * An explicit application agreeing with what the request resolves passes.
     *
     * @return void
     */
    public function testAnExplicitApplicationAgreeingWithTheResolverPasses(): void
    {
        $this->container()->instance(ApplicationResolver::class, new HeaderApplicationResolver);

        config()->set('mfa.applications.' . self::OTHER, ['types' => ['totp'], 'requirement' => 'never']);

        $this->actingAsVerified($this->person(), application: self::OTHER);

        $this->getJson('verified/aal2', ['X-Application' => self::OTHER])->assertOk();
        $this->getJson('verified/aal2', ['X-Application' => 'web'])->assertUnauthorized();
    }

    /**
     * Without an application named, a bound resolver's answer for the current
     * request is where the proofs go, not the guard's name.
     *
     * @return void
     */
    public function testAResolversApplicationIsWhereTheProofsGo(): void
    {
        $this->container()->instance(ApplicationResolver::class, new HeaderApplicationResolver);
        $this->container()->instance('request', HeaderApplicationResolver::requestFor(self::OTHER));

        $user = $this->person();

        $this->actingAsVerified($user);

        self::assertCount(2, $this->heldBy($user, self::OTHER));
        self::assertSame([], $this->heldBy($user, 'web'));
    }

    /**
     * A store whose `begin()` is a no-op and knows no session is refused, for a
     * test to arrange the session first.
     *
     * @return void
     */
    public function testAStoreWithNoSessionIsRefused(): void
    {
        $this->container()->instance(ProofStore::class, new RetainingProofStore);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('no sign-in');

        $this->actingAsVerified($this->person());
    }

    /**
     * A bound recorder begins the sign-in and records its proofs, through a
     * layer the store itself refuses proofs from, and the gate reads them back
     * at the time given.
     *
     * @return void
     */
    public function testABoundRecorderBeginsAndRecordsTheSignIn(): void
    {
        $layer = new LayerWrittenProofStore;
        $user  = $this->person();
        $at    = CarbonImmutable::now()->subMinutes(10);

        $this->container()->instance(ProofStore::class, $layer);
        $this->container()->instance(VerifiedSignInRecorder::class, new LayerRecorder($layer));

        $this->actingAsVerified($user, at: $at);

        $this->getJson('verified/aal2')->assertOk();

        $session = $layer->currentSession($user, 'web');

        self::assertNotNull($session);

        $proofs = $layer->proofs($user, 'web', $session);

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR], array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs));

        foreach ($proofs as $proof) {
            self::assertSame($at->getTimestamp(), $proof->provedAt->getTimestamp());
        }
    }

    /**
     * A recorder may hold the sign-in pending until the further proof completes
     * it, and is handed the time the proofs are made at.
     *
     * @return void
     */
    public function testARecorderMayCompleteAPendingSignInWithTheFurtherProof(): void
    {
        $layer    = new LayerWrittenProofStore;
        $recorder = new PendingLayerRecorder($layer);
        $user     = $this->person();
        $at       = CarbonImmutable::now()->subMinutes(10);

        $this->container()->instance(ProofStore::class, $layer);
        $this->container()->instance(VerifiedSignInRecorder::class, $recorder);

        $this->actingAsVerified($user, at: $at);

        $this->getJson('verified/aal2')->assertOk();

        self::assertNotNull($recorder->startedAt);
        self::assertSame($at->getTimestamp(), $recorder->startedAt->getTimestamp());
    }

    /**
     * Without a recorder, a store whose sign-ins another layer writes cannot be
     * arranged: it begins no sign-in of its own.
     *
     * @return void
     */
    public function testALayerWrittenStoreNeedsARecorder(): void
    {
        $this->container()->instance(ProofStore::class, new LayerWrittenProofStore);

        $this->expectException(\InvalidArgumentException::class);

        $this->actingAsVerified($this->person());
    }

    /**
     * A recorder naming a sign-in the store does not hold as current once its
     * proofs are recorded is refused, before the proofs are evaluated.
     *
     * @return void
     */
    public function testARecorderNamingASignInThatIsNotCurrentIsRefused(): void
    {
        $layer = new LayerWrittenProofStore;

        $this->container()->instance(ProofStore::class, $layer);
        $this->container()->instance(VerifiedSignInRecorder::class, new class ($layer) implements VerifiedSignInRecorder {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Seams\LayerWrittenProofStore  $layer
             */
            public function __construct(

                /** The store whose layer is signed in through. */
                private readonly LayerWrittenProofStore $layer,
            ) {}

            /**
             * Sign in through the layer, but name another sign-in.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @param  \Carbon\CarbonImmutable  $at
             * @return string
             */
            #[\Override]
            public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string
            {
                $this->layer->begin($identity, $application, $this->layer->signIn());

                return 'elsewhere';
            }

            /**
             * Record the proof through the layer.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
             * @return void
             */
            #[\Override]
            public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
            {
                $this->layer->write($proof);
            }
        });

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('is not the proof store\'s current one');

        $this->actingAsVerified($this->person());
    }

    /**
     * A recorder that keeps nothing fails the read-back, naming what was
     * reached: the helper never trusts the recorder's word.
     *
     * @return void
     */
    public function testARecorderThatKeepsNothingFails(): void
    {
        $layer = new LayerWrittenProofStore;

        $this->container()->instance(ProofStore::class, $layer);
        $this->container()->instance(VerifiedSignInRecorder::class, new class ($layer) implements VerifiedSignInRecorder {
            /**
             * Constructor.
             *
             * @param  \Tests\Fixtures\Seams\LayerWrittenProofStore  $layer
             */
            public function __construct(

                /** The store whose layer is signed in through. */
                private readonly LayerWrittenProofStore $layer,
            ) {}

            /**
             * Sign in through the layer and make it current.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @param  \Carbon\CarbonImmutable  $at
             * @return string
             */
            #[\Override]
            public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string
            {
                $session = $this->layer->signIn();

                $this->layer->begin($identity, $application, $session);

                return $session;
            }

            /**
             * Keep nothing.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
             * @return void
             */
            #[\Override]
            public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
            {
                // Nothing is kept.
            }
        });

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('reached unclassified');

        $this->actingAsVerified($this->person());
    }

    /**
     * A first factor a store retains across `begin()` is kept, and the further
     * proof follows it.
     *
     * @return void
     */
    public function testARetainedFirstFactorIsKept(): void
    {
        $user  = $this->person();
        $store = new RetainingProofStore('kept');

        $this->container()->instance(ProofStore::class, $store);

        $store->record($user, SignInProofs::of($user)->inSession('kept')->password(60));

        $this->actingAsVerified($user);

        $proofs = $this->heldBy($user, 'web');

        self::assertCount(2, $proofs);
        self::assertSame('kept', $proofs[0]->binding->sessionId);
        self::assertSame('kept', $proofs[1]->binding->sessionId);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[1]->kind);
    }

    /**
     * Further proofs a store retains are refused, since the time asked for
     * could not be honoured, with nothing recorded after them.
     *
     * @return void
     */
    public function testRetainedFurtherProofsAreRefused(): void
    {
        $user  = $this->person();
        $store = new RetainingProofStore('kept');

        $this->container()->instance(ProofStore::class, $store);

        $store->record($user, SignInProofs::of($user)->inSession('kept')->password(60));
        $store->record($user, SignInProofs::of($user)->inSession('kept')->totp(30));

        try {
            $this->actingAsVerified($user);

            self::fail('The retained proofs must be refused.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('already holds further proofs', $exception->getMessage());
        }

        self::assertCount(2, $this->heldBy($user, 'web'));
    }

    /**
     * A retained first factor later than the time asked for fails: the further
     * proof would precede it and not count.
     *
     * @return void
     */
    public function testARetainedFirstFactorLaterThanTheTimeFails(): void
    {
        $user  = $this->person();
        $store = new RetainingProofStore('kept');

        $this->container()->instance(ProofStore::class, $store);

        $store->record($user, SignInProofs::of($user)->inSession('kept')->password(60));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Requested aal2 with additional verification; reached aal1; unmet: additional_verification, minimum_level.');

        $this->actingAsVerified($user, at: CarbonImmutable::now()->subSeconds(120));
    }

    /**
     * A declared `sms` first factor is not preserved, so it still reaches AAL2:
     * the store's password proof is what the sign-in holds.
     *
     * @return void
     */
    public function testADeclaredSmsFirstFactorStillReachesAal2(): void
    {
        config()->set('mfa.applications.web.first_factor', ['method' => 'sms', 'channel' => 'sms']);

        $this->actingAsVerified($this->person());

        $this->getJson('verified/aal2')->assertOk();
    }

    /**
     * A guard already holding this identity is left alone, so a context its own
     * helper arranged stays; it becomes the default all the same.
     *
     * @return void
     */
    public function testAGuardHoldingTheIdentityIsNotSet(): void
    {
        $user  = $this->person();
        $guard = $this->recordingGuard();

        $guard->arrange(TestUser::query()->findOrFail($user->getKey()));

        $this->actingAsVerified($user, guard: 'recording');

        self::assertSame([], $guard->set);
        self::assertSame('recording', Auth::getDefaultDriver());
    }

    /**
     * A guard holding someone else, or another class with the same key, is
     * given the identity.
     *
     * @return void
     */
    public function testAGuardHoldingAnotherIdentityIsSet(): void
    {
        $user  = $this->person();
        $guard = $this->recordingGuard();

        $guard->arrange($this->person('other@example.test'));

        $this->actingAsVerified($user, guard: 'recording');

        self::assertSame([$user], $guard->set);

        $sameKey = $this->recordingGuard('same-key');
        $other   = new SecondaryUser;

        $other->setAttribute('id', $user->getKey());

        $sameKey->arrange($other);

        $this->actingAsVerified($user, guard: 'same-key');

        self::assertSame([$user], $sameKey->set);
    }

    /**
     * An empty guard is given the identity.
     *
     * @return void
     */
    public function testAnEmptyGuardIsSet(): void
    {
        $user  = $this->person();
        $guard = $this->recordingGuard();

        $this->actingAsVerified($user, guard: 'recording');

        self::assertSame([$user], $guard->set);
    }

    /**
     * Advancing the identity's generation stops the proofs counting.
     *
     * @return void
     */
    public function testAdvancingTheGenerationStopsTheProofsCounting(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user);

        $this->getJson('verified/aal2')->assertOk();

        VerificationGeneration::advance($user);

        $this->getJson('verified/aal2')->assertUnauthorized();
    }

    /**
     * The proofs carry the identity's current generation, so an identity whose
     * generation was advanced before can still be acted as.
     *
     * @return void
     */
    public function testTheProofsCarryTheCurrentGeneration(): void
    {
        $user = $this->person();

        VerificationGeneration::advance($user);

        $this->actingAsVerified($user);

        foreach ($this->heldBy($user, 'web') as $proof) {
            self::assertSame(1, $proof->generation);
        }

        $this->getJson('verified/aal2')->assertOk();
    }

    /**
     * It is a fixture, not a sign-in: no `Login` and no MFA event, though
     * `Authenticated` still fires from `setUser()`.
     *
     * @return void
     */
    public function testItDispatchesNoSignInOrMfaEvent(): void
    {
        $heard = [];

        Event::listen([Login::class, MfaEvent::class, Authenticated::class], static function (object $event) use (&$heard): void {
            $heard[] = $event::class;
        });

        $this->actingAsVerified($this->person());

        self::assertSame([Authenticated::class], $heard);
    }

    /**
     * It enrols no factor.
     *
     * @return void
     */
    public function testItEnrollsNoFactor(): void
    {
        $user = $this->person();

        $this->actingAsVerified($user);

        self::assertFalse($user->isMfaEnabled());
    }

    /**
     * Define the routes the tests call.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->group(['middleware' => 'web'], static function (Router $router): void {
            $router->get('verified/level-free', self::reached(...))->middleware('mfa');
            $router->get('verified/aal1', self::reached(...))->middleware('mfa:level=aal1');
            $router->get('verified/aal2', self::reached(...))->middleware('mfa:level=aal2');
            $router->get('verified/aal3', self::reached(...))->middleware('mfa:level=aal3');
            $router->get('verified/operation', self::reached(...))->middleware('mfa:operation=' . self::OPERATION);
        });
    }

    /**
     * Add a second session guard and its provider.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('auth.guards.secondary', ['driver' => 'session', 'provider' => 'secondary']);
        config()->set('auth.providers.secondary', ['driver' => 'eloquent', 'model' => SecondaryUser::class]);
    }

    /**
     * What a route answers when it is reached.
     *
     * @return string
     */
    private static function reached(): string
    {
        return 'reached';
    }

    /**
     * A person.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(string $email = 'person@example.test'): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->create(['email' => $email]);
    }

    /**
     * A person of the second guard's provider.
     *
     * @return \Tests\Fixtures\Identities\SecondaryUser
     */
    private function secondaryPerson(): SecondaryUser
    {
        /** @var \Tests\Fixtures\Identities\SecondaryUser */
        return SecondaryUser::query()->create(['email' => 'secondary@example.test']);
    }

    /**
     * A recording guard, registered under the name given.
     *
     * @param  string  $name
     * @return \Tests\Fixtures\Testing\RecordingGuard
     */
    private function recordingGuard(string $name = 'recording'): RecordingGuard
    {
        $guard = new RecordingGuard;

        Auth::extend($name, static fn (): RecordingGuard => $guard);

        config()->set('auth.guards.' . $name, ['driver' => $name, 'provider' => 'users']);

        return $guard;
    }

    /**
     * The proofs the bound store holds for the identity's current sign-in on
     * the application, which the helper names afresh each time it acts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private function heldBy(MultiFactorAuthenticatable $identity, string $application): array
    {
        $store   = $this->container()->make(ProofStore::class);
        $session = $store->currentSession($identity, $application);

        return $session === null ? [] : $store->proofs($identity, $application, $session);
    }

    /**
     * A first factor that already rates AAL3 under the levelled policy.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function hardwarePasskeyFirstFactor(TestUser $user): Proof
    {
        $passkey = SignInProofs::of($user)->inSession('kept')->passkey(true, 60);

        return new Proof(
            $passkey->kind,
            $passkey->method,
            $passkey->channel,
            $passkey->reference,
            new ObservedProperties(true, true, phishingResistance: true, keyProtection: KeyProtection::HARDWARE),
            $passkey->provedAt,
            $passkey->binding,
            $passkey->generation,
        );
    }
}
