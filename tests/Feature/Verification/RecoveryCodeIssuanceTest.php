<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Assurance\RefusingCombinationPolicy;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FreshOnceGate;
use Tests\Fixtures\Requirements\RefusingFreshnessGate;
use Tests\Fixtures\Requirements\ScriptedFactorChangeGate;
use Tests\Fixtures\Seams\InterruptingProofStore;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Generating a recovery code set for the person the request serves needs a
 * session fresh enough for the operation that also reaches the level the
 * application sets for issuing them, checked before the codes are drawn and
 * again under the lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeIssuance::class)]
#[CoversClass(RecoveryCodeGeneration::class)]
#[CoversClass(RecoveryCodeService::class)]
final class RecoveryCodeIssuanceTest extends TestCase
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

        \Mockery::close();

        parent::tearDown();
    }

    /**
     * A fresh step-up that reaches the level is issued a set, once.
     *
     * @return void
     */
    public function testAFreshSessionAtTheLevelIsIssuedASet(): void
    {
        $user = $this->steppedUpPerson();

        $generation = $this->mfa()->generateRecoveryCodes(Callers::current());

        self::assertTrue($generation->wasGenerated());
        self::assertNull($generation->reason);
        self::assertCount(10, $generation->codes);
        self::assertSame(10, RecoveryCode::query()->whereNull('replaced_at')->count());
        self::assertTrue($user->isMfaEnabled());
        self::assertCount(1, array_filter($this->reported, static fn (MfaEvent $event): bool => $event instanceof RecoveryCodesGenerated));
    }

    /**
     * A session that is not fresh for the operation is refused, with nothing
     * drawn or replaced.
     *
     * @return void
     */
    public function testASessionNotFreshIsRefused(): void
    {
        $user = $this->steppedUpPerson();

        $this->recoveryCode($user);

        Carbon::setTestNow(now()->addHour());

        $this->assertRefused();
    }

    /**
     * A fresh session below the level is refused, with the same reason.
     *
     * @return void
     */
    public function testASessionBelowTheLevelIsRefused(): void
    {
        $user = $this->steppedUpPerson(['recovery_codes' => ['enabled' => true, 'level' => 'aal3']]);

        $this->recoveryCode($user);

        $this->assertRefused();
    }

    /**
     * The level is the application's: a lower one is met by less.
     *
     * @return void
     */
    public function testALowerLevelIsMetByLess(): void
    {
        $this->enableApplication([
            'recovery_codes' => ['enabled' => true, 'level' => 'aal1'],
            'freshness'      => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]],
        ]);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());
        self::assertCount(10, $this->mfa()->generateRecoveryCodes(Callers::current())->codes);
    }

    /**
     * An email code is accepted without reaching the default level, so it is
     * refused even when fresh.
     *
     * @return void
     */
    public function testAnEmailStepUpDoesNotReachTheDefaultLevel(): void
    {
        $this->enableApplication(['freshness' => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]]]);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->isVerified());

        $this->assertRefused();
    }

    /**
     * A pending session is served nothing here, even one that allows every
     * action.
     *
     * @return void
     */
    public function testAPendingSessionIsServedNothing(): void
    {
        $user = $this->steppedUpPerson();

        $this->pendingSession($user, Requirement::none(), [PendingAction::LIST_FACTORS, PendingAction::SEND_CODE, PendingAction::VERIFY]);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->generateRecoveryCodes(Callers::current())->reason);
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * A person with no sign-in is refused as not fresh, and nobody at all as
     * not found.
     *
     * @return void
     */
    public function testNoSignInIsRefused(): void
    {
        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->generateRecoveryCodes(Callers::current())->reason);

        $user = $this->person();

        $this->totpFactor($user);
        $this->actingAs($user);

        $this->assertRefused();
    }

    /**
     * Freshness is judged under the lock only, once: before it the bound factor
     * change gate is never asked.
     *
     * @return void
     */
    public function testFreshnessIsJudgedUnderTheLockOnly(): void
    {
        $this->steppedUpPerson();

        $gate = new FreshOnceGate;

        $this->container()->instance(FreshnessGate::class, $gate);

        self::assertTrue($this->mfa()->generateRecoveryCodes(Callers::current())->wasGenerated());
        self::assertSame(1, $gate->reads);
    }

    /**
     * A bound factor change gate's refusal under the lock is a refused result,
     * with the reason it gave, and the old set stays intact.
     *
     * @return void
     */
    public function testABoundGatesRefusalKeepsTheOldSet(): void
    {
        $user = $this->steppedUpPerson();
        $old  = $this->recoveryCode($user);
        $gate = new ScriptedFactorChangeGate(refusal: new OperationRefusedException(FailureReason::NOT_FRESH, 'The layer says no.'));

        $this->container()->instance(FactorChangeGate::class, $gate);

        $this->assertRefused();

        self::assertCount(1, $gate->requests);
        self::assertSame(FactorChange::GENERATE_RECOVERY_CODES, $gate->requests[0]->change);
        self::assertNull($gate->requests[0]->factorId);
        self::assertGreaterThan(0, $gate->levels[0]);
        self::assertSame(10, RecoveryCode::query()->whereNull('replaced_at')->count());

        $this->container()->forgetInstance(FactorChangeGate::class);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::recoveryCode($old))->isVerified());
    }

    /**
     * A bound factor change gate is handed the sign-in and the requirement the
     * application configures for the operation.
     *
     * @return void
     */
    public function testABoundGateIsHandedTheSignInAndTheConfiguredRequirement(): void
    {
        $user = $this->steppedUpPerson();
        $gate = new ScriptedFactorChangeGate;

        config()->set('mfa.applications.' . self::APPLICATION . '.freshness', ['mfa.generate_recovery_codes' => 120]);

        $this->container()->instance(FactorChangeGate::class, $gate);

        self::assertTrue($this->mfa()->generateRecoveryCodes(Callers::current())->wasGenerated());
        self::assertSame($this->container()->make(ProofStore::class)->currentSession($user, self::APPLICATION), $gate->requests[0]->session);
        self::assertSame(self::APPLICATION, $gate->requests[0]->application);
        self::assertSame(120, $gate->requests[0]->requirement?->maxAge(RequirementPart::ADDITIONAL_VERIFICATION));
    }

    /**
     * A sign-in that changes under the generation is refused, whatever the gate
     * says of it.
     *
     * @return void
     */
    public function testASignInThatChangesIsRefused(): void
    {
        $this->steppedUpPerson();

        $this->container()->instance(ProofStore::class, new InterruptingProofStore($this->container()->make(ProofStore::class)));
        $this->container()->instance(FreshnessGate::class, new RefusingFreshnessGate(0));

        $this->assertRefused();
    }

    /**
     * Each of the package's own reasons on this path is an answer, not an
     * exception, leaving the old set in place.
     *
     * @return void
     */
    public function testThePackagesOwnReasonsAreAnswers(): void
    {
        $user = $this->steppedUpPerson();

        config()->set('mfa.applications.' . self::APPLICATION . '.recovery_codes.enabled', false);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->generateRecoveryCodes(Callers::current())->reason);

        config()->set('mfa.applications.' . self::APPLICATION . '.recovery_codes.enabled', true);

        Factor::query()->update(['status' => 'pending']);

        self::assertSame(FailureReason::NO_FACTOR, $this->mfa()->generateRecoveryCodes(Callers::current())->reason);
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertTrue($user->exists);
    }

    /**
     * An inactive person is told so, with nothing stored.
     *
     * @return void
     */
    public function testAnInactivePersonIsRefused(): void
    {
        $identity = new NonEloquentIdentity('inactive', mfaEnabled: true, active: false);

        $this->actingAs($identity);

        $this->container()->make(ProofStore::class)->begin($identity, self::APPLICATION, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->generateRecoveryCodes(Callers::current())->reason);
        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * A person the subject type resolver says is not one is served nothing, and
     * a resolver that throws is not read as a refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSubjectTypeResolverDecidesOrPropagates(): void
    {
        $this->steppedUpPerson();

        $resolver = \Mockery::mock(SubjectTypeResolver::class);

        $resolver->shouldReceive('isPerson')->once()->andReturnFalse();
        $resolver->shouldReceive('isPerson')->once()->andThrow(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The resolver refused.'));

        $this->container()->instance(SubjectTypeResolver::class, $resolver);

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->generateRecoveryCodes(Callers::current())->reason);

        try {
            $this->mfa()->generateRecoveryCodes(Callers::current());

            self::fail('The resolver\'s refusal must propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertFalse($exception->byPackage);
        }

        self::assertSame(0, RecoveryCode::query()->count());
    }

    /**
     * A freshness gate's own refusal, asked by the default factor change gate
     * under the lock, stays an exception, with the old set intact and working.
     *
     * @return void
     */
    public function testAFreshnessGatesOwnRefusalPropagatesAndRollsBack(): void
    {
        $user = $this->steppedUpPerson();
        $old  = $this->recoveryCode($user);

        $this->container()->instance(FreshnessGate::class, new RefusingFreshnessGate(1));

        $this->assertPropagates();

        $this->container()->forgetInstance(FreshnessGate::class);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::recoveryCode($old))->isVerified());
    }

    /**
     * A combination policy's own refusal stays an exception at every call it is
     * asked to make, before the lock and under it.
     *
     * @return void
     */
    public function testACombinationPolicysOwnRefusalPropagatesAndRollsBack(): void
    {
        $user = $this->steppedUpPerson();

        $this->recoveryCode($user);

        $real   = $this->container()->make(CombinationPolicy::class);
        $policy = new RefusingCombinationPolicy($real, 0);

        $this->container()->instance(CombinationPolicy::class, $policy);

        self::assertTrue($this->mfa()->generateRecoveryCodes(Callers::current())->wasGenerated());

        $calls = $policy->calls;

        self::assertGreaterThan(1, $calls);

        for ($call = 1; $call <= $calls; $call++) {
            $this->container()->instance(CombinationPolicy::class, new RefusingCombinationPolicy($real, $call));

            $this->assertPropagates();
        }
    }

    /**
     * Rows of what a listener may throw: a refusal marked as the package's own,
     * and one not.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException}>
     */
    public static function listenerRefusals(): iterable
    {
        yield 'marked' => [OperationRefusedException::byPackage(FailureReason::NOT_ACCEPTED, 'A listener refused.')];
        yield 'unmarked' => [new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'A listener refused.')];
    }

    /**
     * A listener's failure once the set has committed is not a refusal of it,
     * whichever kind of refusal it throws: it propagates, with the set stored.
     *
     * @param  \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('listenerRefusals')]
    public function testAListenersRefusalIsNeverAReasonForACommittedSet(OperationRefusedException $refusal): void
    {
        $this->steppedUpPerson();

        Event::listen(RecoveryCodesGenerated::class, static function () use ($refusal): void {
            throw $refusal;
        });

        try {
            $this->mfa()->generateRecoveryCodes(Callers::current());

            self::fail('The listener\'s refusal must propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertSame($refusal, $exception);
        }

        self::assertSame(10, RecoveryCode::query()->whereNull('replaced_at')->count());
    }

    /**
     * Inside an application's transaction the set is reported when that
     * transaction commits, and not before.
     *
     * @return void
     */
    public function testAnOuterTransactionDefersTheEventToItsCommit(): void
    {
        $this->steppedUpPerson();
        $this->forgetReports();

        $connection = DB::connection((new Factor)->getConnectionName());

        $generation = $connection->transaction(function (): RecoveryCodeGeneration {
            $generation = $this->mfa()->generateRecoveryCodes(Callers::current());

            self::assertSame([], $this->reported);

            return $generation;
        });

        self::assertTrue($generation->wasGenerated());
        self::assertCount(1, array_filter($this->reported, static fn (MfaEvent $event): bool => $event instanceof RecoveryCodesGenerated));
    }

    /**
     * A person whose factor was stepped up with, on the application configured
     * for the operation, with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function steppedUpPerson(array $settings = []): TestUser
    {
        $this->enableApplication([
            'freshness' => ['mfa.generate_recovery_codes' => ['additional_verification' => ['max_age' => 600]]],
            ...$settings,
        ]);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());

        return $user;
    }

    /**
     * Generating is refused as not fresh, leaving what was there.
     *
     * @return void
     */
    private function assertRefused(): void
    {
        $before     = RecoveryCode::query()->whereNull('replaced_at')->count();
        $generation = $this->mfa()->generateRecoveryCodes(Callers::current());

        self::assertFalse($generation->wasGenerated());
        self::assertSame(FailureReason::NOT_FRESH, $generation->reason);
        self::assertSame([], $generation->codes);
        self::assertSame($before, RecoveryCode::query()->whereNull('replaced_at')->count());
    }

    /**
     * Generating throws a seam's refusal, unmarked, leaving what was there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function assertPropagates(): void
    {
        $generation = RecoveryCode::query()->whereNull('replaced_at')->max('generation');

        try {
            $this->mfa()->generateRecoveryCodes(Callers::current());

            self::fail('A seam\'s refusal must propagate.');
        } catch (OperationRefusedException $exception) {
            self::assertFalse($exception->byPackage);
        }

        self::assertSame($generation, RecoveryCode::query()->whereNull('replaced_at')->max('generation'));
    }
}
