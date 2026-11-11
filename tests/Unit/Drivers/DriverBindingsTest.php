<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Drivers\DriverBindings;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\PasskeyDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DriverBindings::class)]
final class DriverBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheDriverResolverOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(DriverResolver::class));
        self::assertTrue($this->container()->bound(DriverResolver::class));
        self::assertNotSame($this->container()->make(DriverResolver::class), $this->container()->make(DriverResolver::class));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheShippedDriversWithTheManager(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
        self::assertInstanceOf(TotpDriver::class, $manager->driver('totp'));
        self::assertInstanceOf(EmailDriver::class, $manager->driver('email'));
        self::assertInstanceOf(SmsDriver::class, $manager->driver('sms'));
        self::assertInstanceOf(PasskeyDriver::class, $manager->driver('passkey'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testExtendRegistersDriversThatReadTheConfig(): void
    {
        config()->set('mfa.totp.digits', 8);

        $sender  = FakeEmailSender::fake($this->container());
        $manager = new MfaManager($this->app());

        DriverBindings::extend($manager);

        $totp  = $manager->driver('totp');
        $email = $manager->driver('email');
        $sms   = $manager->driver('sms');

        self::assertInstanceOf(TotpDriver::class, $totp);
        self::assertSame(8, $totp->parameters()->digits);
        self::assertInstanceOf(EmailDriver::class, $email);
        self::assertInstanceOf(SmsDriver::class, $sms);

        $message = CodeMessages::to('ada@example.test');

        $email->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), $message);

        self::assertSame([$message], $sender->sent());
    }

    /**
     * @return void
     */
    public function testTotpFactoryReadsTheTotpSettings(): void
    {
        $defaults = DriverBindings::totp(new Repository)->parameters();

        self::assertSame(['sha1', 6, 30], [$defaults->algorithm, $defaults->digits, $defaults->period]);

        $config = new Repository(['mfa' => ['totp' => ['algorithm' => 'sha256']]]);
        $driver = DriverBindings::totp($config);

        $config->set('mfa.totp.period', 60);

        self::assertSame('sha256', $driver->parameters()->algorithm);
        self::assertSame(60, $driver->parameters()->period);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailFactorySendsThroughTheBoundSender(): void
    {
        $sender  = FakeEmailSender::fake($this->container());
        $message = CodeMessages::to('ada@example.test');

        DriverBindings::email($this->app())->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), $message);

        self::assertSame([$message], $sender->sentTo('ada@example.test'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsFactorySendsThroughTheBoundSender(): void
    {
        $sender  = FakeSmsSender::fake($this->container());
        $message = CodeMessages::to('+447700900123', type: 'sms');

        DriverBindings::sms($this->app())->deliver(new InMemoryFactor(type: 'sms', destination: '+447700900123'), $message);

        self::assertSame([$message], $sender->sentTo('+447700900123'));
    }

    /**
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function app(): Application
    {
        return $this->container();
    }
}
