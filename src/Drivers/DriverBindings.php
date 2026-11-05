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
 * Registers the driver resolver, and builds the shipped TOTP, email, SMS and
 * passkey drivers.
 *
 * The service provider's `mfa` factory registers the drivers against the
 * manager through the standard `extend()` API, so they are indistinguishable
 * from a consumer's own: a consumer replaces one by calling
 * `Mfa::extend('totp', ...)` from their own service provider, or from a
 * container extender or resolving callback on `mfa`, since the manager builds
 * from the most recent registration. Each factory captures nothing: it reads
 * from the container it is handed, the application current when the driver is
 * built, only the settings its driver needs: the TOTP settings from `mfa.totp`
 * and the application's `totp_window`, and the message class from `mfa.codes`,
 * with the application's bound sender. The code's length and lifetime belong to
 * the code service, not the drivers.
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
     * Register the driver resolver.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->bindIf(DriverResolver::class);
    }

    /**
     * Register the shipped TOTP, email, SMS and passkey drivers against the
     * manager.
     *
     * @param  \SineMacula\Laravel\Mfa\MfaManager  $manager
     * @return void
     */
    public static function extend(MfaManager $manager): void
    {
        // Laravel's `Manager::extend()` rebinds each closure to the manager, so
        // the factories are named by class rather than through `self::`, which
        // would then resolve to `MfaManager`.
        $manager->extend('totp', fn (Container $app): TotpDriver => DriverBindings::totp($app->make(Repository::class)));
        $manager->extend('email', fn (Container $app): EmailDriver => DriverBindings::email($app));
        $manager->extend('sms', fn (Container $app): SmsDriver => DriverBindings::sms($app));
        $manager->extend('passkey', fn (): PasskeyDriver => new PasskeyDriver);
    }

    /**
     * Build the TOTP driver over the settings in `mfa.totp`, which it reads on
     * every call.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpDriver
     */
    public static function totp(Repository $config): TotpDriver
    {
        return new TotpDriver(new TotpSettings($config));
    }

    /**
     * Build the email driver with the bound `EmailSender`.
     *
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
     * Build the SMS driver with the bound `SmsSender`.
     *
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
