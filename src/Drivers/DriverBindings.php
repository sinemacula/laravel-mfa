<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Mail\Mailer;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\MfaManager;

/**
 * Registers the driver resolver and the shipped TOTP, email and SMS drivers.
 *
 * The drivers are registered against the manager through the standard
 * `extend()` API when the manager is resolved, so they are indistinguishable
 * from a consumer's own: a consumer replaces one by calling
 * `Mfa::extend('totp', ...)` from their own service provider, since Laravel's
 * `Manager` resolves the most recent registration. Each factory consumes only
 * the slice of config its driver needs.
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
     * Register the driver resolver, and the shipped drivers against the manager
     * once it is resolved.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(DriverResolver::class);

        $app->afterResolving(MfaManager::class, static function (MfaManager $manager, Application $app): void {
            DriverBindings::extend($manager, $app);
        });
    }

    /**
     * Register the shipped TOTP, email and SMS drivers against the manager.
     *
     * @param  \SineMacula\Laravel\Mfa\MfaManager  $manager
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function extend(MfaManager $manager, Application $app): void
    {
        $config = $app->make(Repository::class);

        // Laravel's `Manager::extend()` rebinds each closure to the manager, so
        // the factories are named by class rather than through `self::`, which
        // would then resolve to `MfaManager`.
        $manager->extend('totp', fn (): TotpDriver => DriverBindings::totp($config));
        $manager->extend('email', fn (): EmailDriver => DriverBindings::email($app, $config));
        $manager->extend('sms', fn (): SmsDriver => DriverBindings::sms($app, $config));
    }

    /**
     * Build the TOTP driver from `mfa.drivers.totp` config.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return \SineMacula\Laravel\Mfa\Drivers\TotpDriver
     */
    public static function totp(Repository $config): TotpDriver
    {
        /** @var array{window?: int} $driverConfig */
        $driverConfig = $config->get('mfa.drivers.totp', []);

        return new TotpDriver(window: $driverConfig['window'] ?? 1);
    }

    /**
     * Build the email driver from `mfa.drivers.email` config.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return \SineMacula\Laravel\Mfa\Drivers\EmailDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function email(Application $app, Repository $config): EmailDriver
    {
        /**
         * @var array{
         *     code_length?: int,
         *     expiry?: int,
         *     max_attempts?: int,
         *     alphabet?: ?string,
         *     mailable?: class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>
         * } $driverConfig
         */
        $driverConfig = $config->get('mfa.drivers.email', []);

        return new EmailDriver(
            mailer     : $app->make(Mailer::class),
            mailable   : $driverConfig['mailable']     ?? MfaCodeMessage::class,
            codeLength : $driverConfig['code_length']  ?? 6,
            expiry     : $driverConfig['expiry']       ?? 10,
            maxAttempts: $driverConfig['max_attempts'] ?? 3,
            alphabet   : $driverConfig['alphabet']     ?? null,
        );
    }

    /**
     * Build the SMS driver from `mfa.drivers.sms` config.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return \SineMacula\Laravel\Mfa\Drivers\SmsDriver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function sms(Application $app, Repository $config): SmsDriver
    {
        /**
         * @var array{
         *     code_length?: int,
         *     expiry?: int,
         *     max_attempts?: int,
         *     alphabet?: ?string,
         *     message_template?: string
         * } $driverConfig
         */
        $driverConfig = $config->get('mfa.drivers.sms', []);

        return new SmsDriver(
            gateway        : $app->make(SmsGateway::class),
            messageTemplate: $driverConfig['message_template'] ?? 'Your verification code is: :code',
            codeLength     : $driverConfig['code_length']      ?? 6,
            expiry         : $driverConfig['expiry']           ?? 10,
            maxAttempts    : $driverConfig['max_attempts']     ?? 3,
            alphabet       : $driverConfig['alphabet']         ?? null,
        );
    }
}
