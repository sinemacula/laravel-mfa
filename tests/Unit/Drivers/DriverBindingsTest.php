<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Drivers\DriverBindings;
use SineMacula\Laravel\Mfa\Drivers\DriverResolver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Testing\FakeSmsGateway;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\TestCase;

/**
 * Tests for `DriverBindings`: the driver resolver is shared, the TOTP, email
 * and SMS drivers are registered against the manager, and each factory reads
 * its slice of config with the documented defaults.
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
        config()->set('mfa.drivers.totp.window', 2);
        config()->set('mfa.drivers.email.code_length', 7);
        config()->set('mfa.drivers.sms.code_length', 9);

        $manager = new MfaManager($this->app());

        DriverBindings::extend($manager, $this->app());

        $email = $manager->driver('email');
        $sms   = $manager->driver('sms');

        self::assertSame(2, $this->window($manager->driver('totp')));
        self::assertInstanceOf(EmailDriver::class, $email);
        self::assertSame(7, $email->getCodeLength());
        self::assertInstanceOf(SmsDriver::class, $sms);
        self::assertSame(9, $sms->getCodeLength());
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
        self::assertSame(3, $this->window(DriverBindings::totp(new Repository(['mfa' => ['drivers' => ['totp' => ['window' => 3]]]]))));
    }

    /**
     * The email factory applies the documented defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailFactoryAppliesTheDefaults(): void
    {
        $driver = DriverBindings::email($this->app(), new Repository);

        self::assertSame(MfaCodeMessage::class, $driver->getMailable());
        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    /**
     * The email factory reads every configured value.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEmailFactoryReadsTheConfig(): void
    {
        $driver = DriverBindings::email($this->app(), new Repository(['mfa' => ['drivers' => ['email' => [
            'mailable'     => CustomMfaCodeMessage::class,
            'code_length'  => 8,
            'expiry'       => 5,
            'max_attempts' => 4,
            'alphabet'     => 'ABCDEF',
        ]]]]));

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(5, $driver->getExpiry());
        self::assertSame(4, $driver->getMaxAttempts());
        self::assertSame('ABCDEF', $driver->getAlphabet());
    }

    /**
     * The SMS factory applies the documented defaults.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsFactoryAppliesTheDefaults(): void
    {
        $driver = DriverBindings::sms($this->app(), new Repository);

        self::assertSame('Your verification code is: :code', $driver->getMessageTemplate());
        self::assertSame(6, $driver->getCodeLength());
        self::assertSame(10, $driver->getExpiry());
        self::assertSame(3, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    /**
     * The SMS factory reads every configured value and sends through the bound
     * gateway.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSmsFactoryReadsTheConfig(): void
    {
        $gateway = new FakeSmsGateway;

        $this->container()->instance(SmsGateway::class, $gateway);

        $driver = DriverBindings::sms($this->app(), new Repository(['mfa' => ['drivers' => ['sms' => [
            'message_template' => 'Code :code',
            'code_length'      => 8,
            'expiry'           => 5,
            'max_attempts'     => 4,
            'alphabet'         => 'ABCDEF',
        ]]]]));

        self::assertSame('Code :code', $driver->getMessageTemplate());
        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(5, $driver->getExpiry());
        self::assertSame(4, $driver->getMaxAttempts());
        self::assertSame('ABCDEF', $driver->getAlphabet());
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
