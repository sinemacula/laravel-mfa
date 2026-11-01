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
     */
    public function testExtendRegistersDriversThatReadTheConfig(): void
    {
        config()->set('mfa.totp.digits', 8);
        config()->set('mfa.codes.length', 7);

        $manager = new MfaManager($this->app());

        DriverBindings::extend($manager, $this->app());

        $totp  = $manager->driver('totp');
        $email = $manager->driver('email');
        $sms   = $manager->driver('sms');

        self::assertInstanceOf(TotpDriver::class, $totp);
        self::assertSame(8, $totp->parameters()->digits);
        self::assertInstanceOf(EmailDriver::class, $email);
        self::assertSame(7, $email->getCodeLength());
        self::assertInstanceOf(SmsDriver::class, $sms);
        self::assertSame(7, $sms->getCodeLength());
    }

    /**
     * The TOTP factory builds a driver over the settings in `mfa.totp`, with
     * their defaults when none is set, read as they change.
     *
     * @return void
     */
    public function testTotpFactoryReadsTheTotpSettings(): void
    {
        $defaults = DriverBindings::totp($this->app(), new Repository)->parameters();

        self::assertSame(['sha1', 6, 30], [$defaults->algorithm, $defaults->digits, $defaults->period]);

        $config = new Repository(['mfa' => ['totp' => ['algorithm' => 'sha256']]]);
        $driver = DriverBindings::totp($this->app(), $config);

        $config->set('mfa.totp.period', 60);

        self::assertSame('sha256', $driver->parameters()->algorithm);
        self::assertSame(60, $driver->parameters()->period);
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
        $driver = DriverBindings::email($this->app(), new Repository(['mfa' => ['codes' => [
            'mailable'    => CustomMfaCodeMessage::class,
            'length'      => 8,
            'ttl_minutes' => 5,
        ]]]));

        self::assertSame(CustomMfaCodeMessage::class, $driver->getMailable());
        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(5, $driver->getExpiry());
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

        $driver = DriverBindings::sms($this->app(), new Repository(['mfa' => ['codes' => [
            'sms_message' => 'Code :code',
            'length'      => 8,
            'ttl_minutes' => 5,
        ]]]));

        self::assertSame('Code :code', $driver->getMessageTemplate());
        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(5, $driver->getExpiry());
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
}
