<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * MFA facade.
 *
 * Static interface to the `MfaManager` singleton. Re-exposes the manager's
 * proof, driver, and orchestration surface so consuming applications do not
 * need to resolve the manager out of the container on every call site.
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @method static \SineMacula\Laravel\Mfa\Contracts\FactorDriver driver(?string $driver = null)
 * @method static string getDefaultDriver()
 * @method static class-string<\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> factorModel()
 * @method static static extend(string $driver, \Closure(\Illuminate\Contracts\Foundation\Application): \SineMacula\Laravel\Mfa\Contracts\FactorDriver $callback)
 * @method static bool shouldUse()
 * @method static bool isSetup()
 * @method static list<\SineMacula\Laravel\Mfa\Proofs\Proof> proofs()
 * @method static ?\Illuminate\Support\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> getFactors()
 * @method static ?\SineMacula\Laravel\Mfa\Codes\SendResult challenge(string $driver, \SineMacula\Laravel\Mfa\Contracts\Factor $factor, \SineMacula\Laravel\Mfa\Enums\Purpose $purpose = \SineMacula\Laravel\Mfa\Enums\Purpose::SIGN_IN)
 * @method static bool verify(string $driver, \SineMacula\Laravel\Mfa\Contracts\Factor $factor, string $code, \SineMacula\Laravel\Mfa\Enums\Purpose $purpose = \SineMacula\Laravel\Mfa\Enums\Purpose::SIGN_IN)
 * @method static void enroll(\SineMacula\Laravel\Mfa\Contracts\Factor $factor)
 * @method static void disable(\SineMacula\Laravel\Mfa\Contracts\Factor $factor)
 * @method static list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret> generateRecoveryCodes()
 * @method static bool redeemRecoveryCode(string $code, \SineMacula\Laravel\Mfa\Enums\Purpose $purpose = \SineMacula\Laravel\Mfa\Enums\Purpose::SIGN_IN)
 * @method static ?\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus recoveryCodes()
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @formatter:on
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @see         \SineMacula\Laravel\Mfa\MfaManager
 */
final class Mfa extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    #[\Override]
    protected static function getFacadeAccessor(): string
    {
        return 'mfa';
    }
}
