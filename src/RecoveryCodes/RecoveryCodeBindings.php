<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\MfaManager;

/**
 * Registers the backup-code service, and builds the shipped backup-code driver
 * the service provider's `mfa` factory registers against the manager.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecoveryCodeBindings
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Register the backup-code service.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     * @return void
     */
    public static function register(Application $app): void
    {
        $app->singleton(RecoveryCodeService::class);
    }

    /**
     * Register the shipped backup-code driver against the manager.
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

        // Named by class: `Manager::extend()` rebinds the closure to the
        // manager (see `DriverBindings::extend()`).
        $manager->extend(BackupCodeDriver::NAME, fn (): BackupCodeDriver => RecoveryCodeBindings::backupCodes($config));
    }

    /**
     * Build the backup-code driver with the settings in `mfa.recovery_codes`.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\BackupCodeDriver
     *
     * @throws \InvalidArgumentException
     */
    public static function backupCodes(Repository $config): BackupCodeDriver
    {
        $settings = new RecoveryCodeSettings($config);

        return new BackupCodeDriver(
            codeLength: $settings->length(),
            alphabet  : $settings->alphabet(),
            codeCount : $settings->count(),
        );
    }
}
