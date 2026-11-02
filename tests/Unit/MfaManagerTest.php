<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorChange;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
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
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Pins the manager as a thin entry point: every method hands its arguments to
 * the service of its capability, resolved from the container, and returns that
 * service's answer unchanged. The methods that run a factor through its driver
 * also hand the service the manager itself, as the driver registry, and the
 * recovery code methods hand it the current identity.
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
     * The delegation matrix: manager method, service, service method,
     * arguments and the service's result.
     *
     * @return iterable<string, array{0: string, 1: class-string, 2: string, 3: list<mixed>, 4: mixed}>
     */
    public static function delegations(): iterable
    {
        $factor      = new InMemoryFactor;
        $models      = new Collection;
        $refused     = SendResult::refused(FailureReason::SENDING_CAPPED, 30);
        $requirement = Requirement::none()->withAdditionalVerification(300);
        $summary     = FactorSummary::fromFactor($factor);

        yield 'requirement' => ['requirement', RequirementService::class, 'requirement', [], $requirement];
        yield 'requirement empty' => ['requirement', RequirementService::class, 'requirement', [], Requirement::none()];
        yield 'isFresh true' => ['isFresh', RequirementService::class, 'isFresh', ['mfa.add_factor', $requirement], true];
        yield 'isFresh false' => ['isFresh', RequirementService::class, 'isFresh', ['billing.change_plan', null], false];
        yield 'isSetup true' => ['isSetup', FactorService::class, 'isSetup', [], true];
        yield 'isSetup false' => ['isSetup', FactorService::class, 'isSetup', [], false];
        yield 'getFactors' => ['getFactors', FactorService::class, 'getFactors', [], $models];
        yield 'getFactors null' => ['getFactors', FactorService::class, 'getFactors', [], null];
        yield 'factorModel' => ['factorModel', FactorService::class, 'factorModel', [], Factor::class];
        yield 'proofs' => ['proofs', ProofService::class, 'proofs', [], []];
        yield 'offeredFactors' => ['offeredFactors', FactorOffers::class, 'offered', [], [$summary]];
        yield 'sendCode' => ['sendCode', ChallengeRequests::class, 'sendCode', [$factor->getFactorIdentifier(), Purpose::STEP_UP], $refused];
        yield 'requestAssertion' => ['requestAssertion', ChallengeRequests::class, 'requestAssertion', ['factor-1', Purpose::SIGN_IN], ['challenge' => 'options']];
        $failed = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');

        yield 'verify' => ['verify', VerificationService::class, 'verify', [Submission::factor('factor-1', '123456'), Purpose::STEP_UP], $failed];
        yield 'generateRecoveryCodes' => ['generateRecoveryCodes', RecoveryCodeIssuance::class, 'generate', [], [new RevealedSecret('ABCDEFGHJKLM')]];

        $grant = new RevealedSecret('grant');

        $request = EnrollmentRequest::totp('person@example.test');

        yield 'startEnrollment' => ['startEnrollment', EnrollmentService::class, 'start', [$request], EnrollmentStart::refused(FailureReason::NOT_FOUND)];
        yield 'confirmEnrollment' => ['confirmEnrollment', EnrollmentService::class, 'confirm', [$grant, '123456'], EnrollmentConfirmation::failed(FailureReason::NOT_FOUND)];
        yield 'resendEnrollmentCode' => ['resendEnrollmentCode', EnrollmentService::class, 'resend', [$grant], $refused];
        yield 'cancelEnrollment' => ['cancelEnrollment', EnrollmentService::class, 'cancel', [$grant], false];
        yield 'renameFactor' => ['renameFactor', FactorService::class, 'rename', ['factor-1', 'Work phone'], FactorChange::refused(FailureReason::NOT_FOUND)];
        yield 'setPreferredFactor' => ['setPreferredFactor', FactorService::class, 'setPreferred', ['factor-1'], FactorChange::refused(FailureReason::NOT_FOUND)];
        yield 'disable' => ['disable', LifecycleService::class, 'disable', [$factor], null];
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
    public function testMethodDelegatesToItsCapabilityService(
        string $method,
        string $service,
        string $serviceMethod,
        array $arguments,
        mixed $result,
    ): void {
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
     * A manager method called without its optional argument passes the
     * argument's default to the service: no purpose, which each caller decides.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOptionalArgumentsDefaultToNoPurpose(): void
    {
        $submission = Submission::factor('factor-1', '123456');
        $result     = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');
        $refused    = SendResult::refused(FailureReason::NOT_FOUND);

        $verification = \Mockery::mock($this->container()->make(VerificationService::class));
        $verification->shouldReceive('verify')->once()->with($submission, null)->andReturn($result);

        $requests = \Mockery::mock($this->container()->make(ChallengeRequests::class));
        $requests->shouldReceive('sendCode')->once()->with('factor-1', null)->andReturn($refused);
        $requests->shouldReceive('requestAssertion')->once()->with('factor-1', null)->andReturn([]);

        $requirements = \Mockery::mock($this->container()->make(RequirementService::class));
        $requirements->shouldReceive('isFresh')->once()->with('mfa.add_factor', null)->andReturnFalse();

        $this->container()->instance(VerificationService::class, $verification);
        $this->container()->instance(ChallengeRequests::class, $requests);
        $this->container()->instance(RequirementService::class, $requirements);

        self::assertSame($result, $this->manager()->verify($submission));
        self::assertSame($refused, $this->manager()->sendCode('factor-1'));
        self::assertSame([], $this->manager()->requestAssertion('factor-1'));
        self::assertFalse($this->manager()->isFresh('mfa.add_factor'));
    }

    /**
     * The recovery code status hands the identity the request serves to the
     * recovery code service, and returns its answer.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRecoveryCodeStatusDelegatesForTheCurrentIdentity(): void
    {
        $user = TestUser::query()->create(['email' => 'codes@example.com']);

        $this->actingAs($user);

        $status = new RecoveryCodeStatus(4, 2, CarbonImmutable::now());
        $codes  = \Mockery::mock($this->container()->make(RecoveryCodeService::class));

        $codes->shouldReceive('status')->once()->with($user)->andReturn($status);

        $this->container()->instance(RecoveryCodeService::class, $codes);

        self::assertSame($status, $this->manager()->recoveryCodes());
    }

    /**
     * Without an MFA-capable identity the recovery code methods answer nothing
     * without calling the service: no codes and no status.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRecoveryCodeMethodsAnswerNothingWithoutAnIdentity(): void
    {
        self::assertSame([], $this->manager()->generateRecoveryCodes());
        self::assertSame(0, RecoveryCode::query()->count());

        $codes = \Mockery::mock($this->container()->make(RecoveryCodeService::class));

        $codes->shouldNotReceive('status');

        $this->container()->instance(RecoveryCodeService::class, $codes);

        self::assertNull($this->manager()->recoveryCodes());
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
