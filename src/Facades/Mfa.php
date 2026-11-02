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
 * @method static \SineMacula\Laravel\Mfa\Requirements\Requirement requirement()
 * @method static bool isFresh(string $operation, ?\SineMacula\Laravel\Mfa\Requirements\Requirement $requirement = null)
 * @method static list<\SineMacula\Laravel\Mfa\Proofs\Proof> proofs()
 * @method static list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> factors()
 * @method static ?\SineMacula\Laravel\Mfa\Factors\FactorSummary factor(mixed $factorId)
 * @method static list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> offeredFactors()
 * @method static \SineMacula\Laravel\Mfa\Codes\SendResult sendCode(mixed $factorId, ?\SineMacula\Laravel\Mfa\Enums\Purpose $purpose = null)
 * @method static array<string, mixed> requestAssertion(mixed $factorId, ?\SineMacula\Laravel\Mfa\Enums\Purpose $purpose = null)
 * @method static \SineMacula\Laravel\Mfa\Verification\VerificationResult verify(\SineMacula\Laravel\Mfa\Verification\Submission $submission, ?\SineMacula\Laravel\Mfa\Enums\Purpose $purpose = null)
 * @method static \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart startEnrollment(\SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest $request)
 * @method static \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation confirmEnrollment(\SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string $grant, string $code)
 * @method static \SineMacula\Laravel\Mfa\Codes\SendResult resendEnrollmentCode(\SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string $grant)
 * @method static bool cancelEnrollment(\SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string $grant)
 * @method static \SineMacula\Laravel\Mfa\Factors\FactorChange renameFactor(mixed $factorId, ?string $label)
 * @method static \SineMacula\Laravel\Mfa\Factors\FactorChange setPreferredFactor(mixed $factorId)
 * @method static \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult removeFactor(mixed $factorId)
 * @method static void resetIdentity(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable $identity, \SineMacula\Laravel\Mfa\Events\Actor $actor, string $reason, bool $requireReenrollment = true)
 * @method static bool unlockFactor(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable $identity, mixed $factorId, \SineMacula\Laravel\Mfa\Events\Actor $actor)
 * @method static bool unlockIdentity(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable $identity, \SineMacula\Laravel\Mfa\Events\Actor $actor)
 * @method static \SineMacula\Laravel\Mfa\Lifecycle\PruneResult prune()
 * @method static list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret> generateRecoveryCodes()
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
