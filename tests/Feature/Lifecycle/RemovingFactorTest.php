<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\Lifecycle\RemovalGuard;
use SineMacula\Laravel\Mfa\Lifecycle\RequiredFactorPolicy;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Requirements\SessionReevaluation;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Lifecycle\RecordingSessionRevoker;
use Tests\Fixtures\Lifecycle\ScriptedLastFactorPolicy;
use Tests\Fixtures\Requirements\FixedActiveTenant;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Requirements\ScriptedFactorChangeGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\TestCase;

/**
 * A person removes a factor enrolled through the application they are on: with
 * a fresh step-up, made with another factor where one remains; refused while it
 * is the last factor a requirement needs, asked before the change and again
 * under the lock; revoking the other sessions; invalidating the factor's proofs
 * on this session too; evaluating this session's requirement again; and
 * reported once it has committed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LifecycleService::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(FactorRemovalResult::class)]
#[CoversClass(RemovalGuard::class)]
#[CoversClass(RequirementService::class)]
#[CoversClass(SessionReevaluation::class)]
#[CoversClass(MfaManager::class)]
final class RemovingFactorTest extends TestCase
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
     * A request that serves nobody removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNobodyServedIsNotFound(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user   = TestUser::query()->create(['email' => 'person@example.test']);
        $factor = $this->confirmedFactor($user);

        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * A pending session removes nothing, even one that may list factors, and
     * the guard's user is not served in its place.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionIsNotFound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext(
                $user,
                self::APPLICATION,
                'pending-1',
                SignInProofs::of($user)->inSession('pending-1')->password(),
                Requirement::none()->withAdditionalVerification(),
                [PendingAction::LIST_FACTORS, PendingAction::VERIFY],
                CarbonImmutable::now()->addMinutes(10),
            ),
        ));

        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * An inactive identity is refused before anything else is looked at.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityIsRefused(): void
    {
        $this->actingAs(new NonEloquentIdentity('plain-1', active: false));

        self::assertSame(FailureReason::IDENTITY_INACTIVE, Mfa::removeFactor('missing')->reason);
    }

    /**
     * An id that finds nothing, another person's factor and an id of any other
     * shape get the same answer, whether or not the session is fresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatIsNotTheirsIsNotFound(): void
    {
        $user    = $this->signedInPerson();
        $factor  = $this->confirmedFactor($user);
        $another = TestUser::query()->create(['email' => 'another@example.test']);
        $theirs  = $this->confirmedFactor($another);

        $this->stepUpWith($user, $factor);

        foreach (['missing', $theirs->id, ['id' => $theirs->id], strtoupper($factor->id)] as $id) {
            self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($id)->reason);
        }

        self::assertTrue($this->isStored($theirs));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * An application never deletes a factor enrolled through another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOfAnotherApplicationIsNotFound(): void
    {
        $user  = $this->signedInPerson();
        $other = $this->confirmedFactor($user);

        $other->update(['application' => 'other']);

        $this->stepUpWith($user, $this->confirmedFactor($user));

        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($other->id)->reason);
        self::assertTrue($this->isStored($other));
    }

    /**
     * A pending factor is refused: its enrolment is cancelled or expires.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingFactorIsNotConfirmed(): void
    {
        $user = $this->signedInPerson();

        [$pending] = $this->pendingEnrollmentOf($user);

        self::assertSame(FailureReason::NOT_CONFIRMED, Mfa::removeFactor($pending->id)->reason);
        self::assertTrue($this->isStored($pending));
    }

    /**
     * Removing a factor needs a fresh step-up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStaleSessionIsNotFresh(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor, 86400);

        self::assertSame(FailureReason::NOT_FRESH, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * While another confirmed factor remains, even one that is disabled or that
     * this application does not enable, a step-up made only with the one being
     * removed does not authorise its removal; one made with the other does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStepUpIsMadeWithAnotherFactorWhereOneRemains(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user, 'sms');

        $other->update(['disabled_at' => CarbonImmutable::now()]);

        $this->stepUpWith($user, $factor);

        self::assertSame(FailureReason::NOT_FRESH, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));

        $this->stepUpWith($user, $other);

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
    }

    /**
     * Another factor whose stored status is none the package knows is not read
     * as pending, which would let the factor being removed prove its own
     * removal: the removal throws, and the factor stays.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherFactorWithAnUnknownStatusStopsTheRemoval(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user, 'sms');

        Factor::query()->whereKey($other->id)->toBase()->update(['status' => 'CONFIRMED']);

        $this->stepUpWith($user, $factor);

        try {
            Mfa::removeFactor($factor->id);

            self::fail('An unknown status must not read as pending.');
        } catch (InvalidModelException $exception) {
            self::assertStringContainsString('[status]', $exception->getMessage());
        }

        self::assertTrue($this->isStored($factor));
        self::assertTrue($this->isStored($other));
    }

    /**
     * With no other confirmed factor, a pending one not counting, the step-up
     * may be made with the one being removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOnlyFactorMayBeProvedForItsOwnRemoval(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->pendingEnrollmentOf($user);
        $this->stepUpWith($user, $factor);

        $result = Mfa::removeFactor($factor->id);

        self::assertTrue($result->wasMade());
        self::assertNull($result->reason);
        self::assertSame($factor->id, $result->factor?->id);
        self::assertNull($result->outstanding);
        self::assertFalse($this->isStored($factor));
    }

    /**
     * A stricter requirement a bound gate holds the session to must be met
     * without the factor being removed too: the package's own setting is met by
     * the other factor's older proof, but the gate's only by the removed one's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGatesStricterRequirementIsMetWithoutTheRemovedFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);

        $this->stepUpWith($user, $other, 120);
        $this->stepUpWith($user, $factor);

        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(Requirement::none()->withAdditionalVerification(60)));

        self::assertSame(FailureReason::NOT_FRESH, Mfa::removeFactor($factor->id)->reason);

        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(Requirement::none()->withAdditionalVerification(300)));

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
    }

    /**
     * A gate with no requirement to judge by refuses a removal while another
     * factor remains, and has nothing to judge when none does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGateWithNoRequirementIsNotFresh(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);

        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(null));

        self::assertSame(FailureReason::NOT_FRESH, Mfa::removeFactor($factor->id)->reason);

        $other->delete();

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
    }

    /**
     * A recovery code's proof has no reference, so it counts as made without
     * the factor being removed, where the requirement accepts it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecoveryCodeProofCountsForAnotherFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->confirmedFactor($user);

        $this->container()->make(ProofStore::class)->record(new Proof(
            kind      : ProofKind::RECOVERY_CODE,
            method    : 'recovery_code',
            channel   : null,
            reference : null,
            properties: ObservedProperties::none(),
            provedAt  : CarbonImmutable::now(),
            binding   : $this->bindingOf($user, Purpose::STEP_UP),
            generation: 0,
        ));

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
    }

    /**
     * With a gate that finds the session fresh but no sign-in the store knows
     * of, there is nothing to compare under the lock, so nothing is removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoSignInIsNotFresh(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user   = TestUser::query()->create(['email' => 'person@example.test']);
        $factor = $this->confirmedFactor($user);

        $this->actingAs($user);

        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(Requirement::none()->withAdditionalVerification(60)));

        self::assertSame(FailureReason::NOT_FRESH, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * The last factor a requirement needs stays, whichever application requires
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastRequiredFactorIsRefused(): void
    {
        config()->set('mfa.applications.other', ['types' => ['totp'], 'requirement' => 'always', 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        self::assertSame(FailureReason::LAST_FACTOR, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * The policy is asked before the lock and again under it; a refusal the
     * second time keeps the factor, and is the same answer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePolicyIsAskedAgainUnderTheLock(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $policy = new ScriptedLastFactorPolicy([true, false]);

        $this->stepUpWith($user, $factor);
        $this->container()->instance(LastFactorPolicy::class, $policy);

        self::assertSame(FailureReason::LAST_FACTOR, Mfa::removeFactor($factor->id)->reason);
        self::assertSame(2, $policy->asked);
        self::assertTrue($this->isStored($factor));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * A policy that refuses before the lock is asked once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalBeforeTheLockAsksOnce(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $policy = new ScriptedLastFactorPolicy([false, true]);

        $this->stepUpWith($user, $factor);
        $this->container()->instance(LastFactorPolicy::class, $policy);

        self::assertSame(FailureReason::LAST_FACTOR, Mfa::removeFactor($factor->id)->reason);
        self::assertSame(1, $policy->asked);
    }

    /**
     * Two removals on the last two factors cannot both pass: when the other
     * factor goes between the first ask and the lock, the default policy, asked
     * again under the lock, finds this one is the last. The overlapping
     * database race is proved in `LifecycleRaceTest`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoRacingRemovalsOnlyOnePasses(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION . '.requirement', 'always');

        $user   = $this->signedInPerson();
        $first  = $this->confirmedFactor($user);
        $second = $this->confirmedFactor($user);

        $this->stepUpWith($user, $first);

        $default = $this->container()->make(RequiredFactorPolicy::class);

        $this->container()->instance(LastFactorPolicy::class, new ScriptedLastFactorPolicy(
            [$default, $default],
            static function () use ($first): void {
                $first->delete();
            },
        ));

        self::assertSame(FailureReason::LAST_FACTOR, Mfa::removeFactor($second->id)->reason);
        self::assertTrue($this->isStored($second));
    }

    /**
     * A factor gone by the time the lock is held is not found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorGoneUnderTheLockIsNotFound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        $this->container()->instance(LastFactorPolicy::class, new ScriptedLastFactorPolicy(
            [true, true],
            static function () use ($factor): void {
                $factor->delete();
            },
        ));

        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($factor->id)->reason);
        self::assertSame([], $this->reportedNames());
    }

    /**
     * A sign-in that changed before the lock was held is not acted on: the
     * caller is resolved again under it, as verification does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInThatChangedIsNotFound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        $this->container()->instance(LastFactorPolicy::class, new ScriptedLastFactorPolicy(
            [true, true],
            fn () => $this->container()->make(ProofStore::class)->begin($user, self::APPLICATION, 'another-sign-in'),
        ));

        self::assertSame(FailureReason::NOT_FOUND, Mfa::removeFactor($factor->id)->reason);
        self::assertTrue($this->isStored($factor));
    }

    /**
     * The other sessions stop counting; this one keeps its other proofs, the
     * removed factor's gone, and they are back before any listener runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOtherSessionsAreRevokedAndTheFactorsProofsForgotten(): void
    {
        $user  = $this->signedInPerson();
        $kept  = $this->confirmedFactor($user);
        $gone  = $this->confirmedFactor($user);
        $other = new SessionProofStore(new Store('other-device', new ArraySessionHandler(10)));

        $other->begin($user, self::APPLICATION, 'other-sign-in');
        $other->record(SignInProofs::of($user)->inSession('other-sign-in')->totp());

        $this->stepUpWith($user, $kept);
        $this->stepUpWith($user, $gone);

        $seen = null;

        Event::listen(FactorRemoved::class, function () use ($user, &$seen): void {
            $seen = self::references($this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION));
        });

        self::assertTrue(Mfa::removeFactor($gone->id)->wasMade());
        self::assertSame([], $other->proofs($user, self::APPLICATION));
        self::assertSame([$kept->id], $seen);
        self::assertSame([$kept->id], self::references($this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION)));
    }

    /**
     * The revoker is asked for the other sessions only, inside the change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundRevokerEndsTheOtherSessions(): void
    {
        $user    = $this->signedInPerson();
        $factor  = $this->confirmedFactor($user);
        $revoker = new RecordingSessionRevoker;

        $this->stepUpWith($user, $factor);
        $this->container()->instance(SessionRevoker::class, $revoker);

        $result = Mfa::removeFactor($factor->id);

        self::assertTrue($result->wasMade());
        self::assertNull($result->completion);
        self::assertSame(['others'], $revoker->calls);
        $session = $this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION);

        self::assertSame([['factor' => $factor->id, 'session' => $session]], $revoker->removals);
    }

    /**
     * The bound factor change gate is asked once, under the lock, with the
     * factor and the sign-in, and its refusal is the removal's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundFactorChangeGateIsAskedUnderTheLockOnly(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $gate   = new ScriptedFactorChangeGate;

        $this->container()->instance(FactorChangeGate::class, $gate);

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
        self::assertCount(1, $gate->requests);
        self::assertGreaterThan(0, $gate->levels[0]);
        self::assertSame(FactorChange::REMOVE_FACTOR, $gate->requests[0]->change);
        self::assertSame($factor->id, $gate->requests[0]->factorId);

        $other = $this->confirmedFactor($user);

        $this->container()->instance(FactorChangeGate::class, new ScriptedFactorChangeGate(refusal: new OperationRefusedException(FailureReason::NOT_FRESH, 'The layer says no.')));

        self::assertSame(FailureReason::NOT_FRESH, Mfa::removeFactor($other->id)->reason);
        self::assertTrue($this->isStored($other));
    }

    /**
     * A revoker that judges the current session itself is handed no second
     * judgement: the shortfall is reported, not handed to the transition, and
     * what the revoker returns reaches the caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokerThatJudgesTheSessionItselfIsTheOnlyJudge(): void
    {
        $transition  = new RecordingSessionTransition;
        $requirement = Requirement::none()->withPhishingResistance();
        $completion  = new \stdClass;

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(SessionRevoker::class, new RecordingSessionRevoker(judges: true, completion: $completion));
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement($requirement));

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);

        $this->stepUpWith($user, $other);

        $result = Mfa::removeFactor($factor->id);

        self::assertTrue($result->wasMade());
        self::assertSame($completion, $result->completion);
        self::assertSame($requirement->toArray(), $result->outstanding?->toArray());
        self::assertSame([], $transition->returned);
    }

    /**
     * A revocation that fails rolls the removal back and is not a refusal, even
     * one that throws a refusal. The factor's proofs stay forgotten on this
     * session, which fails closed: restoring them could undo a later
     * invalidation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedRevocationRollsTheRemovalBackAndLeavesTheProofsForgotten(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->recoveryCodesOf($user);
        $this->stepUpWith($user, $factor);

        $revoker = self::createStub(SessionRevoker::class);
        $revoker->method('factorRemoved')->willThrowException(new OperationRefusedException(FailureReason::NOT_FOUND, 'The sessions could not be ended.'));

        $this->container()->instance(SessionRevoker::class, $revoker);

        try {
            Mfa::removeFactor($factor->id);
            self::fail('A failed revocation was expected to propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame('The sessions could not be ended.', $exception->getMessage());
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame(10, RecoveryCode::query()->count());
        self::assertSame([], $this->reportedNames());
        self::assertSame([], self::references($this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION)));
    }

    /**
     * A removal that leaves the session short hands the whole requirement to
     * the session transition and says what is outstanding.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAShortfallReturnsTheSessionToPending(): void
    {
        $transition  = new RecordingSessionTransition;
        $requirement = Requirement::none()->withPhishingResistance();

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement($requirement));

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);

        $this->stepUpWith($user, $other);

        $result = Mfa::removeFactor($factor->id);

        self::assertTrue($result->wasMade());
        self::assertSame($requirement->toArray(), $result->outstanding?->toArray());
        self::assertCount(1, $transition->returned);
        self::assertSame(self::APPLICATION, $transition->returned[0][0]);
    }

    /**
     * The active tenant's requirement is part of what the session is evaluated
     * against again, through the authoritative seam; with no tenant it is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActiveTenantsRequirementIsEvaluatedAgain(): void
    {
        $transition = new RecordingSessionTransition;
        $tenants    = $this->createMock(TenantRequirement::class);

        $tenants->expects(self::once())->method('requirementFor')->with(self::anything(), self::APPLICATION, 'tenant-1')->willReturn(Requirement::none()->withPhishingResistance());

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(TenantRequirement::class, $tenants);

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);
        $third  = $this->confirmedFactor($user);

        $this->stepUpWith($user, $other);

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
        self::assertCount(0, $transition->returned);

        $this->container()->instance(ActiveTenantResolver::class, new FixedActiveTenant('tenant-1'));

        self::assertSame(['phishing_resistance' => ['max_age' => null]], Mfa::removeFactor($third->id)->outstanding?->toArray());
        self::assertCount(1, $transition->returned);
    }

    /**
     * A session transition that cannot gate the session rolls the removal back,
     * and its refusal propagates rather than reading as a refused removal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransitionsRefusalPropagatesAndRollsBack(): void
    {
        $transition = self::createStub(SessionTransition::class);

        $transition->method('returnToPending')->willThrowException(new OperationRefusedException(FailureReason::NOT_FRESH, 'Cannot gate the session.'));

        $this->container()->instance(SessionTransition::class, $transition);
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withPhishingResistance()));
        $this->container()->instance(LastFactorPolicy::class, new ScriptedLastFactorPolicy([true, true]));

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        try {
            Mfa::removeFactor($factor->id);
            self::fail('The transition\'s refusal was expected to propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame('Cannot gate the session.', $exception->getMessage());
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * Removing a factor while another confirmed one remains keeps the recovery
     * codes, and reports the removal alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherFactorKeepsTheRecoveryCodes(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $other  = $this->confirmedFactor($user);

        $this->recoveryCodesOf($user);
        $this->stepUpWith($user, $other);

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
        self::assertSame(10, RecoveryCode::query()->count());
        self::assertSame(['FactorRemoved'], $this->reportedNames());
    }

    /**
     * The last confirmed factor takes the recovery codes with it, a pending
     * factor not counting, and the removal is reported before the codes' end,
     * with no actor since the identity acted itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLastConfirmedFactorTakesTheRecoveryCodes(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->pendingEnrollmentOf($user);
        $this->recoveryCodesOf($user);
        $this->stepUpWith($user, $factor);

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertSame(['FactorRemoved', 'RecoveryCodesRemoved'], $this->reportedNames());
        self::assertInstanceOf(FactorRemoved::class, $this->reported[0]);
        self::assertSame($factor->id, $this->reported[0]->factor->id);
        self::assertSame(self::APPLICATION, $this->reported[0]->context()['application']);
        self::assertNull($this->reported[0]->actor);
    }

    /**
     * With no recovery code set, its removal is not reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoSetIsNoRecoveryCodeEvent(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());
        self::assertSame(['FactorRemoved'], $this->reportedNames());
    }

    /**
     * A factor disabled at the failure ceiling, or of a type no longer enabled,
     * may still be removed by the application that enrolled it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnusableFactorMayBeRemoved(): void
    {
        $user     = $this->signedInPerson();
        $disabled = $this->confirmedFactor($user);
        $retired  = $this->confirmedFactor($user, 'sms');
        $proved   = $this->confirmedFactor($user);

        $disabled->update(['disabled_at' => CarbonImmutable::now()]);

        $this->stepUpWith($user, $proved);

        self::assertTrue(Mfa::removeFactor($disabled->id)->wasMade());
        self::assertTrue(Mfa::removeFactor($retired->id)->wasMade());
    }

    /**
     * Nothing is promoted when the preferred factor goes: removing it leaves
     * none preferred, and reports no change of preference.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingIsPromotedWhenThePreferredFactorGoes(): void
    {
        $user      = $this->signedInPerson();
        $preferred = $this->confirmedFactor($user);
        $other     = $this->confirmedFactor($user);

        $preferred->update(['preferred' => true]);

        $this->stepUpWith($user, $other);

        self::assertTrue(Mfa::removeFactor($preferred->id)->wasMade());
        self::assertFalse(Factor::query()->whereKey($other->id)->sole()->isPreferred());
        self::assertSame(['FactorRemoved'], $this->reportedNames());
    }

    /**
     * Nothing is reported until the removal commits, and a refusal a listener
     * throws after it is not reported as a refused removal: what committed
     * stays committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenersRefusalAfterTheCommitPropagates(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        Event::listen(FactorRemoved::class, static function (): void {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'From a listener.');
        });

        try {
            Mfa::removeFactor($factor->id);
            self::fail('The listener\'s refusal was expected to propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame('From a listener.', $exception->getMessage());
        }

        self::assertFalse($this->isStored($factor));
    }

    /**
     * An outer transaction that rolls back takes the removal and its events
     * with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOuterRollbackReportsNothing(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        try {
            DB::transaction(static function () use ($factor): void {

                self::assertTrue(Mfa::removeFactor($factor->id)->wasMade());

                throw new \RuntimeException('The caller changed its mind.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller changed its mind.', $exception->getMessage());
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * A model event that cancels the deletion rolls the removal back, and it is
     * no refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledDeletionRollsBack(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        Factor::deleting(static fn (): bool => false);

        try {
            Mfa::removeFactor($factor->id);
            self::fail('A cancelled deletion was expected to throw.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('cancelled the factor\'s deletion', $exception->getMessage());
        } finally {
            Factor::flushEventListeners();
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * The references of the proofs that are not first factors.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<?string>
     */
    private static function references(array $proofs): array
    {
        $additional = array_filter($proofs, static fn (Proof $proof): bool => $proof->kind === ProofKind::ADDITIONAL_FACTOR);

        return array_values(array_map(static fn (Proof $proof): ?string => $proof->reference, $additional));
    }
}
