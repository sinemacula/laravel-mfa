<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentService;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorStateCache;
use SineMacula\Laravel\Mfa\Lifecycle\LifecycleService;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Pins the manager as a thin entry point: every method hands its arguments to
 * the service of its capability, resolved from the container, and returns that
 * service's answer unchanged. The methods that run a factor through its driver
 * also hand the service the manager itself, as the driver registry.
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
     * arguments, the service's result and, where the service runs a driver,
     * that the manager is passed first as the driver registry.
     *
     * @return iterable<string, array{0: string, 1: class-string, 2: string, 3: list<mixed>, 4: mixed, 5?: bool}>
     */
    public static function delegations(): iterable
    {
        $factor = new InMemoryFactor;
        $models = new Collection;

        yield 'shouldUse true' => ['shouldUse', RequirementService::class, 'shouldUse', [], true];
        yield 'shouldUse false' => ['shouldUse', RequirementService::class, 'shouldUse', [], false];
        yield 'isSetup true' => ['isSetup', FactorService::class, 'isSetup', [], true];
        yield 'isSetup false' => ['isSetup', FactorService::class, 'isSetup', [], false];
        yield 'getFactors' => ['getFactors', FactorService::class, 'getFactors', [], $models];
        yield 'getFactors null' => ['getFactors', FactorService::class, 'getFactors', [], null];
        yield 'factorModel' => ['factorModel', FactorService::class, 'factorModel', [], Factor::class];
        yield 'hasEverVerified true' => ['hasEverVerified', ProofService::class, 'hasEverVerified', [], true];
        yield 'hasEverVerified false' => ['hasEverVerified', ProofService::class, 'hasEverVerified', [], false];
        yield 'hasExpired with window' => ['hasExpired', ProofService::class, 'hasExpired', [5], true];
        yield 'hasExpired without window' => ['hasExpired', ProofService::class, 'hasExpired', [null], false];
        yield 'markVerified' => ['markVerified', ProofService::class, 'markVerified', [], null];
        yield 'forgetVerification' => ['forgetVerification', ProofService::class, 'forgetVerification', [], null];
        yield 'challenge' => ['challenge', VerificationService::class, 'challenge', ['totp', $factor, Purpose::SIGN_IN], null, true];
        yield 'challenge for a code' => ['challenge', VerificationService::class, 'challenge', ['email', $factor, Purpose::STEP_UP], SendResult::refused(FailureReason::SENDING_CAPPED, 30), true];
        yield 'verify true' => ['verify', VerificationService::class, 'verify', ['totp', $factor, '123456', Purpose::SIGN_IN], true, true];
        yield 'verify false' => ['verify', VerificationService::class, 'verify', ['totp', $factor, '654321', Purpose::STEP_UP], false, true];
        yield 'enroll' => ['enroll', EnrollmentService::class, 'enroll', [$factor], null];
        yield 'disable' => ['disable', LifecycleService::class, 'disable', [$factor], null];
        yield 'issueBackupCodes with count' => ['issueBackupCodes', RecoveryCodeService::class, 'issueBackupCodes', [3], ['A', 'B', 'C'], true];
        yield 'issueBackupCodes without count' => ['issueBackupCodes', RecoveryCodeService::class, 'issueBackupCodes', [null], [], true];
        yield 'clearCache for every identity' => ['clearCache', FactorStateCache::class, 'clear', [null], null];
        yield 'clearCache for an identity' => ['clearCache', FactorStateCache::class, 'clear', [new TestUser], null];
    }

    /**
     * Each manager method calls the same method on its capability's service
     * with the arguments it was given, preceded by the manager where the
     * service runs a driver, and returns the service's result.
     *
     * @param  string  $method
     * @param  class-string  $service
     * @param  string  $serviceMethod
     * @param  list<mixed>  $arguments
     * @param  mixed  $result
     * @param  bool  $withRegistry
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
        bool $withRegistry = false,
    ): void {
        // Resolved before the double is bound: resolving the manager checks the
        // configuration, which reads the factor model through the service.
        $manager  = $this->manager();
        $expected = $withRegistry ? [$manager, ...$arguments] : $arguments;

        $double = \Mockery::mock($this->container()->make($service));
        $double->shouldReceive($serviceMethod)->once()->with(...$expected)->andReturn($result);

        $this->container()->instance($service, $double);

        $call = [$manager, $method];

        self::assertIsCallable($call);

        $returned = $call(...$arguments);

        self::assertSame($result, $returned);
    }

    /**
     * A manager method called without its optional argument passes the
     * argument's default to the service: `null`, or the sign-in purpose.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOptionalArgumentsDefaultToNull(): void
    {
        $proofs = \Mockery::mock($this->container()->make(ProofService::class));
        $proofs->shouldReceive('hasExpired')->once()->with(null)->andReturnTrue();

        $codes = \Mockery::mock($this->container()->make(RecoveryCodeService::class));
        $codes->shouldReceive('issueBackupCodes')->once()->with($this->manager(), null)->andReturn([]);

        $cache = \Mockery::mock($this->container()->make(FactorStateCache::class));
        $cache->shouldReceive('clear')->once()->with(null);

        $factor       = new InMemoryFactor;
        $verification = \Mockery::mock($this->container()->make(VerificationService::class));
        $verification->shouldReceive('challenge')->once()->with($this->manager(), 'totp', $factor, Purpose::SIGN_IN)->andReturnNull();
        $verification->shouldReceive('verify')->once()->with($this->manager(), 'totp', $factor, '123456', Purpose::SIGN_IN)->andReturnTrue();

        $this->container()->instance(ProofService::class, $proofs);
        $this->container()->instance(RecoveryCodeService::class, $codes);
        $this->container()->instance(FactorStateCache::class, $cache);
        $this->container()->instance(VerificationService::class, $verification);

        self::assertTrue($this->manager()->hasExpired());
        self::assertSame([], $this->manager()->issueBackupCodes());
        self::assertNull($this->manager()->challenge('totp', $factor));
        self::assertTrue($this->manager()->verify('totp', $factor, '123456'));

        $this->manager()->clearCache();
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
