<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Drivers\DriverBindings;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;

/**
 * Tests for `DriverBindings`: the driver resolver is shared, the TOTP, email
 * and SMS drivers are registered against the manager, and each factory reads
 * its slice of config with the documented defaults and delivers through the
 * bound sender.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DriverBindings::class)]
final class DriverBindingsTest extends TestCase
{
    /**
     * The driver resolver is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheDriverResolverAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(DriverResolver::class));
        self::assertSame($this->container()->make(DriverResolver::class), $this->container()->make(DriverResolver::class));
    }

    /**
     * The resolved manager has the TOTP, email and SMS drivers.
     *
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
    }

    /**
     * The drivers registered against a manager read the application's config.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \ReflectionException
     */
    public function testExtendRegistersDriversThatReadTheConfig(): void
    {
        config()->set('mfa.totp.window', 2);
        config()->set('mfa.codes.mailable', CustomMfaCodeMessage::class);
        config()->set('mfa.codes.sms_message', 'Code :code');

        $manager = new MfaManager($this->app());

        DriverBindings::extend($manager, $this->app());

        $email = $manager->driver('email');
        $sms   = $manager->driver('sms');

        self::assertSame(2, $this->window($manager->driver('totp')));
        self::assertInstanceOf(EmailDriver::class, $email);
        self::assertSame(CustomMfaCodeMessage::class, $email->getMailable());
        self::assertInstanceOf(SmsDriver::class, $sms);
        self::assertSame('Code :code', $sms->getMessageTemplate());
    }

    /**
     * The TOTP factory defaults the window to one step and reads a configured
     * one.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testTotpFactoryReadsTheWindow(): void
    {
        self::assertSame(1, $this->window(DriverBindings::totp(new Repository)));
        self::assertSame(3, $this->window(DriverBindings::totp(new Repository(['mfa' => ['totp' => ['window' => 3]]]))));
    }

    /**
     * The email factory applies the documented default message class.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailFactoryAppliesTheDefaults(): void
    {
        $driver = DriverBindings::email($this->app(), new Repository);

        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
    }

    /**
     * The email factory reads the configured message class and delivers through
     * the bound email sender.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailFactoryReadsTheConfigAndSendsThroughTheBoundSender(): void
    {
        $sender = FakeEmailSender::fake($this->container());

        $driver = DriverBindings::email($this->app(), new Repository(['mfa' => ['codes' => [
            'mailable' => CustomMfaCodeMessage::class,
        ]]]));

        $driver->deliver(new InMemoryFactor(type: 'email', destination: 'ada@example.test'), '123456', CarbonImmutable::now()->addMinutes(5));

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
        self::assertCount(1, $sender->sentTo('ada@example.test'));
        self::assertInstanceOf(CustomMfaCodeMessage::class, $sender->sentTo('ada@example.test')[0]['message']);
        self::assertSame('123456', $sender->lastCodeTo('ada@example.test'));
    }

    /**
     * The SMS factory applies the documented default message.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsFactoryAppliesTheDefaults(): void
    {
        $driver = DriverBindings::sms($this->app(), new Repository);

        self::assertSame('Your verification code is: :code', $driver->getMessageTemplate());
    }

    /**
     * The SMS factory reads the configured message and delivers through the
     * bound SMS sender.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsFactoryReadsTheConfigAndSendsThroughTheBoundSender(): void
    {
        $sender = FakeSmsSender::fake($this->container());

        $driver = DriverBindings::sms($this->app(), new Repository(['mfa' => ['codes' => [
            'sms_message' => 'Code :code',
        ]]]));

        $driver->deliver(new InMemoryFactor(type: 'sms', destination: '+447700900123'), '123456', CarbonImmutable::now()->addMinutes(5));

        self::assertSame('Code :code', $driver->getMessageTemplate());
        self::assertSame('Code 123456', $sender->lastMessageTo('+447700900123'));
    }

    /**
     * Return the application as the foundation contract.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function app(): Application
    {
        return $this->container();
    }

    /**
     * Read the TOTP driver's window, which it does not expose.
     *
     * @param  mixed  $driver
     * @return mixed
     *
     * @throws \ReflectionException
     */
    private function window(mixed $driver): mixed
    {
        self::assertInstanceOf(TotpDriver::class, $driver);

        return (new \ReflectionProperty($driver, 'window'))->getValue($driver);
    }
}
