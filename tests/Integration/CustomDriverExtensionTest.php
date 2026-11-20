<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\Fixtures\Drivers\RecordingFactorDriver;
use Tests\Fixtures\Drivers\VoiceCodeDriver;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Factors\MyDriverFactor;
use Tests\TestCase;

/**
 * A consumer's driver serves its own type end to end, and one registered under
 * a shipped driver's name wins whether made through the facade, a container
 * extender or a resolving callback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class CustomDriverExtensionTest extends TestCase
{
    use ArrangesEnrollment;

    /** @var string */
    private const string PHONE = '+447700900123';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testCustomDriverResolvesToRegisteredInstance(): void
    {
        $driver = new RecordingFactorDriver;

        Mfa::extend('my_driver', static fn () => $driver);

        self::assertSame($driver, Mfa::driver('my_driver'));
    }

    /**
     * @return void
     */
    public function testCustomDriverVerifyCallReachesRegisteredInstance(): void
    {
        $driver = new RecordingFactorDriver;

        Mfa::extend('my_driver', static fn () => $driver);

        Mfa::driver('my_driver')->verify(new MyDriverFactor, 'correct', new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::SIGN_IN));

        self::assertSame(1, $driver->verifyCalls);
    }

    /**
     * The override wins even after the built-in driver has been resolved once.
     *
     * @return void
     */
    public function testConsumerCanOverrideBuiltInTotpDriver(): void
    {
        $marker = new class implements FactorDriver {
            use DescribesNoChannel;

            /**
             * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
             * @param  string  $code
             * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
             * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
             */
            #[\Override]
            public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
            {
                return CodeCheck::ACCEPTED;
            }
        };

        self::assertNotSame($marker, Mfa::driver('totp'));

        Mfa::extend('totp', static fn (): FactorDriver => $marker);

        self::assertSame(
            $marker,
            Mfa::driver('totp'),
            'Mfa::extend(\'totp\', ...) must override the built-in TOTP driver',
        );
    }

    /**
     * The shipped drivers are registered before extenders run.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testContainerExtenderOverrideOfTotpWins(): void
    {
        $marker = new NoopFactorDriver;

        $this->container()->forgetInstance('mfa');
        $this->container()->extend('mfa', static fn (MfaManager $manager): MfaManager => $manager->extend('totp', fn (): FactorDriver => $marker));

        self::assertSame($marker, $this->manager()->driver('totp'));
    }

    /**
     * The shipped drivers are registered before resolving callbacks run.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvingCallbackOverrideOfTotpWins(): void
    {
        $marker = new NoopFactorDriver;

        $this->container()->forgetInstance('mfa');
        $this->container()->resolving('mfa', static function (MfaManager $manager) use ($marker): void {
            $manager->extend('totp', fn (): FactorDriver => $marker);
        });

        self::assertSame($marker, $this->manager()->driver('totp'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testResolvingCallbackSeesTheShippedDrivers(): void
    {
        $seen = null;

        $this->container()->forgetInstance('mfa');
        $this->container()->resolving('mfa', static function (MfaManager $manager) use (&$seen): void {
            $seen = $manager->driver('totp');
        });

        $this->manager();

        self::assertInstanceOf(TotpDriver::class, $seen);
    }

    /**
     * The driver normalises the stored destination and delivers every code.
     *
     * @return void
     */
    public function testACustomDeliveredTypeEnrollsSendsAndVerifies(): void
    {
        $driver = new VoiceCodeDriver;

        $this->enableApplication(['types' => ['voice']]);

        Mfa::extend('voice', static fn (): VoiceCodeDriver => $driver);

        $this->reauthenticatedPerson();

        $start = Mfa::startEnrollment(Callers::current(), EnrollmentRequest::delivered('voice', ' +44 (7700) 900123 '));

        self::assertTrue($start->hasStarted());

        $factor = $this->pendingFactorOf($start);

        self::assertSame(self::PHONE, $factor->getDestination());
        self::assertSame(self::PHONE, $driver->calls[0]['destination']);
        self::assertTrue(Mfa::confirmEnrollment(Callers::current(), $this->grantOf($start), $driver->calls[0]['code'])->isConfirmed());

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(60));

        $challenge = Mfa::sendCode(Callers::current(), $factor->id)->challengeId;

        self::assertNotNull($challenge);
        self::assertCount(2, $driver->calls);

        $code = $driver->calls[1]['code'];

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->reason);

        $proof = Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $code))->proof;

        self::assertNotNull($proof);
        self::assertSame('voice', $proof->method);
        self::assertSame(['kind' => 'sms', 'reference' => self::PHONE], $proof->channel?->toArray());
    }

    /**
     * @return void
     */
    public function testAReplacedSmsDriverDeliversInsteadOfTheBoundSender(): void
    {
        $driver = new VoiceCodeDriver;
        $sender = FakeSmsSender::fake($this->container());

        $this->enableApplication(['types' => ['sms']]);

        Mfa::extend('sms', static fn (): VoiceCodeDriver => $driver);

        $factor    = $this->factorOf($this->signedInPerson(), ['type' => 'sms', 'destination' => self::PHONE]);
        $challenge = Mfa::sendCode(Callers::current(), $factor->id)->challengeId;

        self::assertNotNull($challenge);
        self::assertSame([], $sender->sent());
        self::assertCount(1, $driver->calls);
        self::assertTrue(Mfa::verify(Callers::current(), Submission::challenge($factor->id, $challenge, $driver->calls[0]['code']))->isVerified());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
