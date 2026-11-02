<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\PendingEnrollments;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\EnrollmentAbandoned;
use SineMacula\Laravel\Mfa\Events\FactorRemoved;
use SineMacula\Laravel\Mfa\Events\FactorsReset;
use SineMacula\Laravel\Mfa\Events\LockoutLifted;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Lifecycle\IdentityReset;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\Concerns\ArrangesLifecycle;
use Tests\Fixtures\Lifecycle\RecordingSessionRevoker;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * Resetting an identity: everything it holds goes in one change, every proof
 * and session with it, the obligation is recorded, the events come in order
 * once it commits, and a verification racing it fails or has its proof
 * invalidated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityReset::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversClass(PendingEnrollments::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(MfaManager::class)]
final class ResettingIdentityTest extends TestCase
{
    use ArrangesLifecycle;

    /** @var string The reason every reset is made for. */
    private const string REASON = 'Lost phone, identity checked by support.';

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
     * A blank reason is refused before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReasonIsRequired(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        foreach (['', "  \n"] as $reason) {
            try {
                $this->container()->make(IdentityReset::class)->reset($user, self::actor(), $reason, true);
                self::fail('A blank reason was expected to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A reset needs a reason.', $exception->getMessage());
            }
        }

        self::assertTrue($this->isStored($factor));
    }

    /**
     * A machine holds no factors, and is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineIsRefused(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);
        $types  = self::createStub(SubjectTypeResolver::class);

        $types->method('isPerson')->willReturn(false);

        $this->container()->instance(SubjectTypeResolver::class, $types);

        try {
            Mfa::resetIdentity($user, self::actor(), self::REASON);
            self::fail('A machine was expected to be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::MACHINE_IDENTITY, $exception->reason);
        }

        self::assertTrue($this->isStored($factor));
    }

    /**
     * Everything the identity holds goes, with nobody signed in as it; every
     * session is revoked and the generation moves even if the bound revoker's
     * does not; another identity is untouched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetRemovesEverythingAndRevokesEverySession(): void
    {
        $user    = $this->signedInPerson();
        $other   = TestUser::query()->create(['email' => 'other@example.test']);
        $kept    = $this->confirmedFactor($other);
        $totp    = $this->confirmedFactor($user);
        $passkey = $this->confirmedFactor($user, 'passkey', self::CREDENTIAL);

        $this->pendingEnrollmentOf($user);
        $this->recoveryCodesOf($user);
        $this->recoveryCodesOf($other);
        $this->stepUpWith($user, $totp);

        IdentityState::query()->where('authenticatable_id', (string) $user->id)->update(['locked_until' => CarbonImmutable::now()->addHour(), 'consecutive_failures' => 7]);

        $generation = VerificationGeneration::current($user);
        $revoker    = new RecordingSessionRevoker;

        $this->container()->instance(SessionRevoker::class, $revoker);

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertSame([$kept->id], Factor::query()->pluck('id')->all());
        self::assertSame(0, Enrollment::query()->count());
        self::assertSame(10, RecoveryCode::query()->count());
        self::assertSame(0, PasskeyAssociation::query()->where('factor_id', $passkey->id)->count());
        self::assertSame(['all'], $revoker->calls);

        $state = IdentityState::query()->where('authenticatable_id', (string) $user->id)->sole();

        self::assertNull($state->locked_until);
        self::assertSame(0, $state->consecutive_failures);
        self::assertGreaterThan($generation, VerificationGeneration::current($user));
        self::assertSame([], $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION));
    }

    /**
     * An inactive identity can be reset, by a console command with no caller at
     * all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityCanBeReset(): void
    {
        $identity = new NonEloquentIdentity('plain-1', active: false);

        $factor = Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-1',
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        Mfa::resetIdentity($identity, self::actor(), self::REASON);

        self::assertFalse($this->isStored($factor));
    }

    /**
     * Resetting the identity the request serves invalidates its own proofs too:
     * they are not kept for it, and its next protected request finds none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResettingTheCurrentCallerInvalidatesItsProofs(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->stepUpWith($user, $factor);

        self::assertNotSame([], Mfa::proofs());

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertSame([], Mfa::proofs());
        self::assertFalse(Mfa::requirement()->isEmpty());
    }

    /**
     * The events come once the change commits, every lockout first, each factor
     * in id order by how far it got, the codes, and the reset itself last, each
     * naming the actor where it can; a lockout that had ended is not reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEventsComeInOrderNamingTheActor(): void
    {
        $user   = $this->signedInPerson();
        $locked = $this->confirmedFactor($user);
        $ended  = $this->confirmedFactor($user);
        $actor  = self::actor();

        [$pending] = $this->pendingEnrollmentOf($user);

        $this->recoveryCodesOf($user);

        $locked->update(['locked_until' => CarbonImmutable::now()->addMinutes(10)]);
        $ended->update(['locked_until' => CarbonImmutable::now()->subMinutes(10)]);

        IdentityState::query()->where('authenticatable_id', (string) $user->id)->update(['locked_until' => CarbonImmutable::now()->addHour()]);

        Mfa::resetIdentity($user, $actor, self::REASON);

        self::assertSame(
            ['LockoutLifted', 'LockoutLifted', 'FactorRemoved', 'FactorRemoved', 'EnrollmentAbandoned', 'RecoveryCodesRemoved', 'FactorsReset'],
            $this->reportedNames(),
        );

        [$factorLockout, $identityLockout, $first, $second, $abandoned, $codes, $reset] = $this->reported;

        self::assertInstanceOf(LockoutLifted::class, $factorLockout);
        self::assertSame($locked->id, $factorLockout->factor?->id);
        self::assertSame($actor, $factorLockout->actor);
        self::assertInstanceOf(LockoutLifted::class, $identityLockout);
        self::assertNull($identityLockout->factor);
        self::assertSame($actor, $identityLockout->actor);
        self::assertInstanceOf(FactorRemoved::class, $first);
        self::assertSame($locked->id, $first->factor->id);
        self::assertSame($actor, $first->actor);
        self::assertInstanceOf(FactorRemoved::class, $second);
        self::assertSame($ended->id, $second->factor->id);
        self::assertInstanceOf(EnrollmentAbandoned::class, $abandoned);
        self::assertSame($pending->id, $abandoned->factor->id);
        self::assertInstanceOf(RecoveryCodesRemoved::class, $codes);
        self::assertSame($actor, $codes->actor);
        self::assertInstanceOf(FactorsReset::class, $reset);
        self::assertSame($actor, $reset->actor);
        self::assertSame(self::REASON, $reset->reason);
        self::assertTrue($reset->reenrollmentRequired);
        self::assertSame((string) $user->id, (string) $reset->context()['identity_id']);
    }

    /**
     * With no set, no codes' removal is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoSetIsNoRecoveryCodeEvent(): void
    {
        $user = $this->signedInPerson();

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertSame(['FactorsReset'], $this->reportedNames());
    }

    /**
     * A failure inside the change undoes it all, and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureRollsTheWholeResetBack(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->recoveryCodesOf($user);

        $this->container()->instance(SessionRevoker::class, new RecordingSessionRevoker(fails: true));

        try {
            Mfa::resetIdentity($user, self::actor(), self::REASON);
            self::fail('A revocation that failed was expected to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The sessions could not be ended.', $exception->getMessage());
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame(10, RecoveryCode::query()->count());
        self::assertFalse(ReenrollmentObligation::isRequired($user));
        self::assertSame([], $this->reportedNames());
    }

    /**
     * A write a model event cancels rolls the reset back: the identity's state
     * is never left with its failures or lockout intact while the rest goes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledStateSaveRollsTheResetBack(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        VerificationGeneration::advance($user);

        IdentityState::query()->where('authenticatable_id', (string) $user->id)->update(['consecutive_failures' => 7]);

        IdentityState::saving(static fn (): bool => false);

        try {
            Mfa::resetIdentity($user, self::actor(), self::REASON);
            self::fail('A cancelled save was expected to throw.');
        } catch (WriteCanceledException $exception) {
            self::assertStringContainsString('failures in a row', $exception->getMessage());
        } finally {
            IdentityState::flushEventListeners();
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame(7, IdentityState::query()->where('authenticatable_id', (string) $user->id)->sole()->consecutive_failures);
        self::assertSame([], $this->reportedNames());
    }

    /**
     * An outer transaction that rolls back takes the reset and its events with
     * it, and a listener's exception after the commit leaves it committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRollbackAndListenerFailures(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        try {
            DB::transaction(static function () use ($user): void {

                Mfa::resetIdentity($user, self::actor(), self::REASON);

                throw new \RuntimeException('The caller changed its mind.');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('The caller changed its mind.', $exception->getMessage());
        }

        self::assertTrue($this->isStored($factor));
        self::assertSame([], $this->reportedNames());

        Event::listen(FactorsReset::class, static function (): void {
            throw new \RuntimeException('From a listener.');
        });

        try {
            Mfa::resetIdentity($user, self::actor(), self::REASON);
            self::fail('The listener\'s exception was expected to propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame('From a listener.', $exception->getMessage());
        }

        self::assertFalse($this->isStored($factor));
    }

    /**
     * A verification that read the factor before a reset took it fails under
     * the lock, as not found, and records no proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationTheResetBeatsFails(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactorOf($user);
        $code   = AuthenticatorApp::code($factor);
        $raced  = false;

        Factor::retrieved(static function () use ($user, &$raced): void {

            if ($raced) {
                return;
            }

            $raced = true;

            Mfa::resetIdentity($user, self::actor(), self::REASON);
        });

        $result = Mfa::verify(Submission::factor($factor->id, $code));

        Factor::flushEventListeners();

        self::assertTrue($raced);
        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame([], $this->container()->make(ProofStore::class)->proofs($user, self::APPLICATION));
    }

    /**
     * A verification that committed first keeps its success, which
     * serialisation cannot undo, but the reset invalidates its proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationThatCommittedFirstLosesItsProof(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactorOf($user);

        $this->recordFirstFactor($user);

        self::assertTrue(Mfa::verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertNotSame([], Mfa::proofs());

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertSame([], Mfa::proofs());
    }

    /**
     * A recovery code submitted after a reset finds no set, and one redeemed
     * before it leaves a proof the reset invalidates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecoveryCodeRacingAReset(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        $this->recordFirstFactor($user);

        $codes = $this->container()->make(RecoveryCodeService::class)->generate($user);

        self::assertTrue(Mfa::verify(Submission::recoveryCode($codes[0]->reveal()))->isVerified());
        self::assertNotSame([], Mfa::proofs());

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertSame([], Mfa::proofs());
        self::assertFalse(Mfa::verify(Submission::recoveryCode($codes[1]->reveal()))->isVerified());
        self::assertFalse($this->isStored($factor));
    }

    /**
     * An enrolment grant from before a reset confirms nothing after it: the
     * enrolment is gone, whichever came first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOldEnrollmentGrantConfirmsNothing(): void
    {
        $user  = $this->signedInPerson();
        $store = $this->container()->make(ProofStore::class);

        $store->record(SignInProofs::of($user)->password(60));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        $start = Mfa::startEnrollment(EnrollmentRequest::totp('person@example.test'));

        self::assertTrue($start->hasStarted());

        $code = AuthenticatorApp::code(Factor::query()->whereKey($start->factor?->id)->sole());

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertFalse(Mfa::confirmEnrollment((string) $start->grant?->reveal(), $code)->isConfirmed());
        self::assertSame(0, Factor::query()->count());
        self::assertTrue(ReenrollmentObligation::isRequired($user));
    }

    /**
     * The obligation is recorded by default, survives a new sign-in and a new
     * read of the identity, applies in every application, and ends when a
     * factor is confirmed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheObligationSurvivesAndEndsAtTheNextConfirmation(): void
    {
        $user = $this->signedInPerson();

        $this->confirmedFactor($user);

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        /** @var \Tests\Fixtures\Identities\TestUser $fresh */
        $fresh = TestUser::query()->findOrFail($user->id);

        self::assertTrue(ReenrollmentObligation::isRequired($fresh));
        self::assertFalse(Mfa::requirement()->isEmpty());

        $store = $this->container()->make(ProofStore::class);

        $this->actingAs($fresh);

        $store->begin($fresh, self::APPLICATION, 'after-the-reset');
        $store->record(SignInProofs::of($fresh)->inSession('after-the-reset')->password(60));

        $this->container()->instance(Reauthenticator::class, new FreshReauthenticator($store));

        $start = Mfa::startEnrollment(EnrollmentRequest::totp('person@example.test'));

        self::assertTrue($start->hasStarted());
        self::assertTrue(ReenrollmentObligation::isRequired($fresh));

        $code = AuthenticatorApp::code(Factor::query()->whereKey($start->factor?->id)->sole());

        self::assertTrue(Mfa::confirmEnrollment((string) $start->grant?->reveal(), $code)->isConfirmed());
        self::assertFalse(ReenrollmentObligation::isRequired($fresh));
    }

    /**
     * A reset that states no obligation clears one left by an earlier reset,
     * and says so.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetCanStateThatNoObligationFollows(): void
    {
        $user = $this->signedInPerson();

        Mfa::resetIdentity($user, self::actor(), self::REASON);

        self::assertTrue(ReenrollmentObligation::isRequired($user));

        Mfa::resetIdentity($user, self::actor(), self::REASON, false);

        self::assertFalse(ReenrollmentObligation::isRequired($user));

        $reset = $this->reported[1];

        self::assertInstanceOf(FactorsReset::class, $reset);
        self::assertFalse($reset->reenrollmentRequired);
    }

    /**
     * Record the first factor the session's verifications come after.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function recordFirstFactor(TestUser $user): void
    {
        $this->container()->make(ProofStore::class)->record(SignInProofs::of($user)->password());
    }

    /**
     * A confirmed TOTP factor of the user's with a secret the test can answer.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function totpFactorOf(TestUser $user): Factor
    {
        $factor = $this->confirmedFactor($user);

        $factor->update(AuthenticatorApp::FACTOR);

        return $factor;
    }
}
