<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Drivers\DriverBindings;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\RequestAttributePendingSessionResolver;
use Tests\Fixtures\Drivers\NoopFactorDriver;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * The manager keeps nothing a request gave it, checked on a copy of the
 * application made current per request as a long-running server does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(DriverBindings::class)]
final class MfaManagerLongRunningTest extends TestCase
{
    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->makeCurrent($this->container());

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testTheManagerDeclaresNoProperty(): void
    {
        $declared = array_filter(
            (new \ReflectionClass(MfaManager::class))->getProperties(),
            static fn (\ReflectionProperty $property): bool => $property->getDeclaringClass()->getName() === MfaManager::class,
        );

        self::assertSame([], $declared);
    }

    /**
     * A service built in the current application, reading its request and
     * seams; back on the booted one, it answers from there.
     *
     * @return void
     */
    public function testADelegationAnswersFromTheCurrentApplication(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new RequestAttributePendingSessionResolver);

        $manager = $this->manager();
        $user    = TestUser::query()->create(['email' => 'person@example.test']);
        $factor  = $this->factorOf($user);

        $this->container()->instance('request', Request::create('/'));

        $sandbox = $this->sandbox();
        $request = Request::create('/');

        $request->attributes->set(RequestAttributePendingSessionResolver::ATTRIBUTE, $this->pendingSessionOf($user));

        $sandbox->instance('request', $request);

        self::assertSame([$factor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, $manager->factors(Callers::current())));

        $this->makeCurrent($this->container());

        self::assertSame([], $manager->factors(Callers::current()));
    }

    /**
     * With the configuration and sender of the current application.
     *
     * @return void
     */
    public function testShippedDriversAreBuiltFromTheCurrentApplication(): void
    {
        $manager = $this->manager();

        $this->container()->make(Repository::class)->set('mfa.totp.digits', 6);

        $bootedEmail = FakeEmailSender::fake($this->container());
        $bootedSms   = FakeSmsSender::fake($this->container());

        $sandbox = $this->sandbox();
        $config  = clone $sandbox->make(Repository::class);

        $sandbox->instance('config', $config);

        $config->set('mfa.totp.digits', 8);

        $email = FakeEmailSender::fake($sandbox);
        $sms   = FakeSmsSender::fake($sandbox);

        $totp = $manager->driver('totp');

        self::assertInstanceOf(TotpDriver::class, $totp);
        self::assertSame(8, $totp->parameters()->digits);

        $emailDriver = $manager->driver('email');

        self::assertInstanceOf(EmailDriver::class, $emailDriver);

        $factor = new InMemoryFactor(type: 'email', destination: 'ada@example.test');

        $emailDriver->deliver($factor, CodeMessages::to('ada@example.test'));

        self::assertCount(1, $email->sent());

        $smsDriver = $manager->driver('sms');

        self::assertInstanceOf(SmsDriver::class, $smsDriver);
        self::assertSame($sms, (fn () => $this->sender)->call($smsDriver));
        self::assertNotSame($bootedSms, $sms);

        $this->makeCurrent($this->container());

        $booted = $manager->driver('email');

        self::assertInstanceOf(EmailDriver::class, $booted);

        $booted->deliver($factor, CodeMessages::to('ada@example.test', '654321'));

        self::assertSame('654321', $bootedEmail->lastCodeTo('ada@example.test'));
        self::assertCount(1, $email->sent());
    }

    /**
     * A driver registered at boot is handed the application current when it is
     * built.
     *
     * @return void
     */
    public function testACustomCreatorReceivesTheCurrentApplication(): void
    {
        $manager = $this->manager();
        $handed  = [];

        $manager->extend('custom', function (mixed $app) use (&$handed): NoopFactorDriver {
            $handed[] = $app;

            return new NoopFactorDriver;
        });

        $sandbox = $this->sandbox();

        $manager->driver('custom');

        $this->makeCurrent($this->container());

        $manager->driver('custom');

        self::assertSame([$sandbox, $this->container()], $handed);
    }

    /**
     * No driver, the booted container, and the configuration its constructor
     * read.
     *
     * @return void
     */
    public function testTheManagersOwnFieldsKeepNothingOfACopy(): void
    {
        $booted  = $this->container();
        $manager = $this->manager();
        $config  = (fn () => $this->config)->call($manager);

        $sandbox = $this->sandbox();

        $sandbox->instance('config', clone $sandbox->make(Repository::class));

        $manager->driver('totp');
        $manager->driver('email');
        $manager->factors(Callers::current());

        self::assertSame([], $manager->getDrivers());
        self::assertSame($booted, $manager->getContainer());
        self::assertSame($config, (fn () => $this->config)->call($manager));
    }

    /**
     * The inherited setter would store a request's application.
     *
     * @return void
     */
    public function testTheContainerCannotBeSet(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The MFA manager resolves from the current application, and holds no container of a request\'s.');

        $this->manager()->setContainer($this->sandbox());
    }

    /**
     * Two resolutions are two objects, and the latest registration wins however
     * late.
     *
     * @return void
     */
    public function testADriverIsBuiltOnEveryCall(): void
    {
        $manager = $this->manager();

        self::assertNotSame($manager->driver('totp'), $manager->driver('totp'));

        $replacement = new NoopFactorDriver;

        $manager->extend('totp', fn (): FactorDriver => $replacement);

        self::assertSame($replacement, $manager->driver('totp'));
    }

    /**
     * As Laravel's manager normalises it: nothing is the default, and an enum
     * is its value.
     *
     * @return void
     */
    public function testADriversNameIsNormalized(): void
    {
        $manager = $this->manager();

        $replacement = new NoopFactorDriver;

        $manager->extend(FactorStatus::CONFIRMED->value, fn (): FactorDriver => $replacement);

        self::assertSame($replacement, $manager->driver(FactorStatus::CONFIRMED));
        self::assertInstanceOf(TotpDriver::class, $manager->driver());
        self::assertInstanceOf(TotpDriver::class, $manager->driver(null));
        self::assertInstanceOf(TotpDriver::class, $manager->driver(''));
    }

    /**
     * As a long-running server makes one for each request.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function sandbox(): Application
    {
        $sandbox = clone $this->container();

        $this->makeCurrent($sandbox);

        return $sandbox;
    }

    /**
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    private function makeCurrent(Application $app): void
    {
        $app->instance('app', $app);
        $app->instance(Container::class, $app);

        Container::setInstance($app);

        Facade::clearResolvedInstances();
        Facade::setFacadeApplication($app);
    }

    /**
     * Allowing factors to be listed.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private function pendingSessionOf(TestUser $user): PendingContext
    {
        return new PendingContext(
            $user,
            'web',
            SignInProofs::SESSION,
            SignInProofs::of($user)->password(),
            Requirement::none(),
            [PendingAction::LIST_FACTORS],
            CarbonImmutable::now()->addMinutes(10),
        );
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function factorOf(TestUser $user): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
        ]);
    }

    /**
     * The manager the booted application resolves.
     *
     * @return \SineMacula\Laravel\Mfa\MfaManager
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
