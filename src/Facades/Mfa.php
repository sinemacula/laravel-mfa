<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * MFA facade.
 *
 * Static interface to the `MfaManager` singleton. It annotates exactly the
 * manager's surface: the methods it declares, and the inherited `extend()`. An
 * annotation is documentation, not an allowlist: `getDrivers()`,
 * `getContainer()` and `forgetDrivers()`, inherited from Laravel's manager,
 * stay callable as inherited infrastructure, and any method neither declares is
 * refused.
 *
 * @formatter:off
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @method static \SineMacula\Laravel\Mfa\Contracts\FactorDriver driver(\UnitEnum|string|null $driver = null)
 * @method static \SineMacula\Laravel\Mfa\MfaManager extend(string $driver, \Closure(\Illuminate\Contracts\Container\Container): \SineMacula\Laravel\Mfa\Contracts\FactorDriver $callback)
 * @method static string getDefaultDriver()
 * @method static class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> factorModel()
 * @method static \SineMacula\Laravel\Mfa\Requirements\Requirement requirement(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static bool isFresh(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, string $operation, ?\SineMacula\Laravel\Mfa\Requirements\Requirement $requirement = null)
 * @method static list<\SineMacula\Laravel\Mfa\Proofs\Proof> proofs(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static array{accepted: bool, multifactor: bool, factor_types: list<string>, level: string, phishing_resistant: bool, user_verification: bool, last_verification_age_seconds: ?int, has_confirmed_factor: bool} authenticationContext(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> factors(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static ?\SineMacula\Laravel\Mfa\Factors\FactorSummary factor(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, mixed $factorId)
 * @method static list<\SineMacula\Laravel\Mfa\Factors\FactorSummary> offeredFactors(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static \SineMacula\Laravel\Mfa\Factors\FactorChange renameFactor(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, mixed $factorId, ?string $label)
 * @method static \SineMacula\Laravel\Mfa\Factors\FactorChange setPreferredFactor(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, mixed $factorId)
 * @method static \SineMacula\Laravel\Mfa\Codes\SendResult sendCode(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, mixed $factorId, ?\SineMacula\Laravel\Mfa\Enums\Purpose $purpose = null)
 * @method static \SineMacula\Laravel\Mfa\Passkeys\AssertionRequest requestAssertion(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, mixed $factorId, ?\SineMacula\Laravel\Mfa\Enums\Purpose $purpose = null)
 * @method static \SineMacula\Laravel\Mfa\Verification\VerificationResult verify(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, \SineMacula\Laravel\Mfa\Verification\Submission $submission, ?\SineMacula\Laravel\Mfa\Enums\Purpose $purpose = null)
 * @method static \SineMacula\Laravel\Mfa\Enrollment\EnrollmentStart startEnrollment(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, \SineMacula\Laravel\Mfa\Enrollment\EnrollmentRequest $request)
 * @method static \SineMacula\Laravel\Mfa\Enrollment\EnrollmentConfirmation confirmEnrollment(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string $grant, string $code)
 * @method static \SineMacula\Laravel\Mfa\Codes\SendResult resendEnrollmentCode(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string $grant)
 * @method static bool cancelEnrollment(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string $grant)
 * @method static \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration generateRecoveryCodes(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static ?\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus recoveryCodeStatus(\SineMacula\Laravel\Mfa\Context\CallerContext $caller)
 * @method static \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult removeFactor(\SineMacula\Laravel\Mfa\Context\CallerContext $caller, mixed $factorId)
 * @method static void resetIdentity(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable $identity, \SineMacula\Laravel\Mfa\Events\Actor $actor, string $reason, bool $requireReenrollment = true, ?\SineMacula\Laravel\Mfa\Context\ClientContext $client = null)
 * @method static bool unlockFactor(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable $identity, mixed $factorId, \SineMacula\Laravel\Mfa\Events\Actor $actor, ?\SineMacula\Laravel\Mfa\Context\ClientContext $client = null)
 * @method static bool unlockIdentity(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable $identity, \SineMacula\Laravel\Mfa\Events\Actor $actor, ?\SineMacula\Laravel\Mfa\Context\ClientContext $client = null)
 * @method static void forgetIdentity(\Illuminate\Contracts\Auth\Authenticatable $identity)
 * @method static \SineMacula\Laravel\Mfa\Lifecycle\PruneResult prune()
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
