<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * MFA facade.
 *
 * Static interface to the `MfaManager` singleton. Re-exposes the manager's
 * verification-state, driver, and orchestration surface so consuming
 * applications do not need to resolve the manager out of the container on
 * every call site.
 *
 * @method static \SineMacula\Laravel\Mfa\Contracts\FactorDriver driver(?string $driver = null)
 * @method static string getDefaultDriver()
 * @method static class-string<\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> factorModel()
 * @method static static extend(string $driver, \Closure(\Illuminate\Contracts\Foundation\Application): \SineMacula\Laravel\Mfa\Contracts\FactorDriver $callback)
 * @method static bool shouldUse()
 * @method static bool isSetup()
 * @method static bool hasEverVerified()
 * @method static bool hasExpired(?int $expiresAfter = null)
 * @method static void markVerified()
 * @method static void forgetVerification()
 * @method static void clearCache(?\Illuminate\Contracts\Auth\Authenticatable $identity = null)
 * @method static ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> getFactors()
 * @method static void challenge(string $driver, \SineMacula\Laravel\Mfa\Contracts\Factor $factor)
 * @method static bool verify(string $driver, \SineMacula\Laravel\Mfa\Contracts\Factor $factor, string $code)
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
