<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorChange;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult;
use SineMacula\Laravel\Mfa\Lifecycle\ForgetIdentity;
use SineMacula\Laravel\Mfa\Lifecycle\IdentityReset;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Passkeys\AssertionRequest;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeIssuance;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\FactorOffers;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Pins the manager as a thin entry point: every method hands its arguments to
 * the service of its capability, resolved from the container, and returns that
 * service's answer unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerTest extends TestCase
{
    /**
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * The default driver is TOTP.
     *
     * @return void
     */
    public function testDefaultDriverIsTotp(): void
    {
        self::assertSame('totp', $this->manager()->getDefaultDriver());
    }

    /**
     * The delegation matrix: manager method, service, service method, arguments
     * and the service's result.
     *
     * @return iterable<string, array{0: string, 1: class-string, 2: string, 3: list<mixed>, 4: mixed}>
     */
    public static function delegations(): iterable
    {
        $factor      = new InMemoryFactor;
        $refused     = SendResult::refused(FailureReason::SENDING_CAPPED, 30);
        $requirement = Requirement::none()->withAdditionalVerification(300);
        $summary     = FactorSummary::fromFactor($factor);
        $caller      = CallerContext::forIdentity(new NonEloquentIdentity('caller-1'), 'web');

        yield 'requirement' => ['requirement', RequirementService::class, 'requirement', [$caller], $requirement];
        yield 'requirement empty' => ['requirement', RequirementService::class, 'requirement', [$caller], Requirement::none()];
        yield 'isFresh true' => ['isFresh', RequirementService::class, 'isFresh', [$caller, 'mfa.add_factor', $requirement], true];
        yield 'isFresh false' => ['isFresh', RequirementService::class, 'isFresh', [$caller, 'billing.change_plan', null], false];
        yield 'factors' => ['factors', FactorService::class, 'factors', [$caller], [$summary]];
        yield 'factor' => ['factor', FactorService::class, 'factor', [$caller, 'factor-1'], $summary];
        yield 'factor missing' => ['factor', FactorService::class, 'factor', [$caller, 'factor-1'], null];
        yield 'factorModel' => ['factorModel', FactorService::class, 'factorModel', [], Factor::class];
        yield 'proofs' => ['proofs', ProofService::class, 'proofs', [$caller], []];
        yield 'offeredFactors' => ['offeredFactors', FactorOffers::class, 'offered', [$caller], [$summary]];
        yield 'sendCode' => ['sendCode', ChallengeRequests::class, 'sendCode', [$caller, $factor->getFactorIdentifier(), Purpose::STEP_UP], $refused];

        $started = AssertionRequest::started(['challenge' => 'options']);

        yield 'requestAssertion' => ['requestAssertion', ChallengeRequests::class, 'requestAssertion', [$caller, 'factor-1', Purpose::SIGN_IN], $started];

        $failed = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');

        yield 'verify' => ['verify', VerificationService::class, 'verify', [$caller, Submission::factor('factor-1', '123456'), Purpose::STEP_UP], $failed];

        $generated = RecoveryCodeGeneration::generated([new RevealedSecret('ABCDEFGHJKLM')]);

        yield 'generateRecoveryCodes' => ['generateRecoveryCodes', RecoveryCodeIssuance::class, 'generate', [$caller], $generated];
        yield 'recoveryCodeStatus' => ['recoveryCodeStatus', RecoveryCodeService::class, 'statusOfCaller', [$caller], new RecoveryCodeStatus(4, 2, CarbonImmutable::now())];
        yield 'recoveryCodeStatus of nobody' => ['recoveryCodeStatus', RecoveryCodeService::class, 'statusOfCaller', [$caller], null];

        $grant = new RevealedSecret('grant');

        $request = EnrollmentRequest::totp('person@example.test');

        yield 'startEnrollment' => ['startEnrollment', EnrollmentService::class, 'start', [$caller, $request], EnrollmentStart::refused(FailureReason::NOT_FOUND)];
        $unconfirmed = EnrollmentConfirmation::failed(FailureReason::NOT_FOUND);

        yield 'confirmEnrollment' => ['confirmEnrollment', EnrollmentService::class, 'confirm', [$caller, $grant, '123456'], $unconfirmed];
        yield 'resendEnrollmentCode' => ['resendEnrollmentCode', EnrollmentService::class, 'resend', [$caller, $grant], $refused];
        yield 'cancelEnrollment' => ['cancelEnrollment', EnrollmentService::class, 'cancel', [$caller, $grant], false];
        yield 'renameFactor' => ['renameFactor', FactorService::class, 'rename', [$caller, 'factor-1', 'Work phone'], FactorChange::refused(FailureReason::NOT_FOUND)];
        yield 'setPreferredFactor' => ['setPreferredFactor', FactorService::class, 'setPreferred', [$caller, 'factor-1'], FactorChange::refused(FailureReason::NOT_FOUND)];

        $identity = new NonEloquentIdentity('plain-1');
        $actor    = new Actor('admin', '9');

        yield 'removeFactor' => ['removeFactor', LifecycleService::class, 'removeFactor', [$caller, 'factor-1'], FactorRemovalResult::refused(FailureReason::NOT_FOUND)];
        yield 'unlockFactor' => ['unlockFactor', LifecycleService::class, 'unlockFactor', [$identity, 'factor-1', $actor, new ClientContext('192.0.2.7')], true];
        yield 'enableFactor' => ['enableFactor', LifecycleService::class, 'enableFactor', [$identity, 'factor-1', $actor, new ClientContext('192.0.2.7')], true];
        yield 'unlockIdentity' => ['unlockIdentity', LifecycleService::class, 'unlockIdentity', [$identity, $actor, null], false];
        yield 'resetIdentity' => ['resetIdentity', IdentityReset::class, 'reset', [$identity, $actor, 'Lost phone.', false, null], null];
        yield 'forgetIdentity' => ['forgetIdentity', ForgetIdentity::class, 'forget', [$identity], null];
    }

    /**
     * Each manager method calls the same method on its capability's service
     * with the arguments it was given, and returns the service's result.
     *
     * @param  string  $method
     * @param  class-string  $service
     * @param  string  $serviceMethod
     * @param  list<mixed>  $arguments
     * @param  mixed  $result
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('delegations')]
    public function testMethodDelegatesToItsCapabilityService(string $method, string $service, string $serviceMethod, array $arguments, mixed $result): void
    {
        // Resolved before the double is bound: resolving the manager checks the
        // configuration, which reads the factor model through the service.
        $manager = $this->manager();

        $double = \Mockery::mock($this->container()->make($service));
        $double->shouldReceive($serviceMethod)->once()->with(...$arguments)->andReturn($result);

        $this->container()->instance($service, $double);

        $call = [$manager, $method];

        self::assertIsCallable($call);

        $returned = $call(...$arguments);

        self::assertSame($result, $returned);
    }

    /**
     * A reset obliges the identity to enrol again unless it says otherwise.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResetObligesReenrollmentByDefault(): void
    {
        $identity = new NonEloquentIdentity('plain-1');
        $actor    = new Actor('admin', '9');
        $manager  = $this->manager();
        $reset    = \Mockery::mock($this->container()->make(IdentityReset::class));

        $reset->shouldReceive('reset')->once()->with($identity, $actor, 'Lost phone.', true, null);

        $this->container()->instance(IdentityReset::class, $reset);

        $manager->resetIdentity($identity, $actor, 'Lost phone.');
    }

    /**
     * A manager method called without its optional argument passes the
     * argument's default to the service: no purpose, which each caller decides.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOptionalArgumentsDefaultToNoPurpose(): void
    {
        $caller     = Callers::current();
        $submission = Submission::factor('factor-1', '123456');
        $result     = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');
        $refused    = SendResult::refused(FailureReason::NOT_FOUND);
        $assertion  = AssertionRequest::refused(FailureReason::NOT_FOUND);

        $verification = \Mockery::mock($this->container()->make(VerificationService::class));
        $verification->shouldReceive('verify')->once()->with($caller, $submission, null)->andReturn($result);

        $requests = \Mockery::mock($this->container()->make(ChallengeRequests::class));
        $requests->shouldReceive('sendCode')->once()->with($caller, 'factor-1', null)->andReturn($refused);
        $requests->shouldReceive('requestAssertion')->once()->with($caller, 'factor-1', null)->andReturn($assertion);

        $requirements = \Mockery::mock($this->container()->make(RequirementService::class));
        $requirements->shouldReceive('isFresh')->once()->with($caller, 'mfa.add_factor', null)->andReturnFalse();

        $this->container()->instance(VerificationService::class, $verification);
        $this->container()->instance(ChallengeRequests::class, $requests);
        $this->container()->instance(RequirementService::class, $requirements);

        self::assertSame($result, $this->manager()->verify($caller, $submission));
        self::assertSame($refused, $this->manager()->sendCode($caller, 'factor-1'));
        self::assertSame($assertion, $this->manager()->requestAssertion($caller, 'factor-1'));
        self::assertFalse($this->manager()->isFresh($caller, 'mfa.add_factor'));
    }

    /**
     * The recovery code status is that of the identity the request serves.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRecoveryCodeStatusIsTheCallers(): void
    {
        $this->actingAs(TestUser::query()->create(['email' => 'codes@example.com']));

        $status = $this->manager()->recoveryCodeStatus(Callers::current());

        self::assertNotNull($status);
        self::assertFalse($status->exists());
        self::assertSame(0, $status->remaining);
    }

    /**
     * Without an MFA-capable identity the recovery code methods change and read
     * nothing: generating is refused, and there is no status.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRecoveryCodeMethodsServeNobodyWithoutAnIdentity(): void
    {
        $generation = $this->manager()->generateRecoveryCodes(Callers::current());

        self::assertFalse($generation->wasGenerated());
        self::assertSame(FailureReason::NOT_FOUND, $generation->reason);
        self::assertSame(0, RecoveryCode::query()->count());
        self::assertNull($this->manager()->recoveryCodeStatus(Callers::current()));
    }

    /**
     * A method neither the manager nor Laravel's declares is refused, not
     * forwarded to the default driver, whose raw check runs outside attempts,
     * proofs and events. Neither the method's arguments nor the driver are
     * reached.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUndeclaredMethodIsRefusedAndNeverReachesTheDriver(): void
    {
        $driver = \Mockery::mock(FactorDriver::class);

        $driver->shouldNotReceive('confirm');

        $manager = $this->manager();

        $manager->extend('totp', fn (): FactorDriver => $driver);

        $calls = [
            // @phpstan-ignore method.notFound
            static fn () => $manager->confirm('secret-code'),
            // @phpstan-ignore staticMethod.notFound
            static fn () => Mfa::confirm('secret-code'),
        ];

        foreach ($calls as $call) {
            try {
                $call();

                self::fail('The method must be refused.');
            } catch (\BadMethodCallException $exception) {
                self::assertSame(sprintf('Method %s::confirm() does not exist.', MfaManager::class), $exception->getMessage());
            }
        }
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
