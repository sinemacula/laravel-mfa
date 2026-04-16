<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * MFA facade.
 *
 * Provides a static interface to the MFA manager for convenient
 * access throughout the application.
 *
 * @method static \SineMacula\Laravel\Mfa\Contracts\FactorDriver driver(string|null $driver = null)
 * @method static bool shouldUse()
 * @method static bool isSetup()
 * @method static bool hasExpired(int|null $expiresAfter = null)
 * @method static void clearCache(\Illuminate\Contracts\Auth\Authenticatable|null $identity = null)
 * @method static \Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>|null getFactors()
 * @method static string getDefaultDriver()
 * @method static static extend(string $driver, \Closure(\Illuminate\Contracts\Foundation\Application): \SineMacula\Laravel\Mfa\Contracts\FactorDriver $callback)
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @see         \SineMacula\Laravel\Mfa\MfaManager
 */
class Mfa extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'mfa';
    }
}
