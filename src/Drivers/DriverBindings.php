<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\MfaManager;

/**
 * Registers the shipped drivers through `extend()`, so a consumer replaces one
 * with `Mfa::extend()` like any other. Factories capture nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DriverBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(DriverResolver::class);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\MfaManager  $manager
     * @return void
     */
    public static function extend(MfaManager $manager): void
    {
        // `Manager::extend()` rebinds each closure to the manager, where
        // `self::` would mean `MfaManager`.
        $manager->extend('totp', fn (Container $app): TotpDriver => DriverBindings::totp($app->make(Repository::class)));
        $manager->extend('email', fn (Container $app): EmailDriver => DriverBindings::email($app));
        $manager->extend('sms', fn (Container $app): SmsDriver => DriverBindings::sms($app));
        $manager->extend('passkey', fn (): PasskeyDriver => new PasskeyDriver);
    }

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpDriver
     */
    public static function totp(Repository $config): TotpDriver
    {
        return new TotpDriver(new TotpSettings($config));
    }

    /**
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @return \SineMacula\Laravel\Mfa\Drivers\EmailDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function email(Container $app): EmailDriver
    {
        return new EmailDriver($app->make(EmailSender::class));
    }

    /**
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @return \SineMacula\Laravel\Mfa\Drivers\SmsDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function sms(Container $app): SmsDriver
    {
        return new SmsDriver($app->make(SmsSender::class));
    }
}
