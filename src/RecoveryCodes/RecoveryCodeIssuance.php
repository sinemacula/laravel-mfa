<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\FactorChanges;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Issues a new recovery code set to the person the request serves, only on a
 * session the bound `Contracts\FactorChangeGate` authorises for
 * `mfa.generate_recovery_codes` (by default, one fresh enough for it) that also
 * reaches the level the application sets for issuing them.
 *
 * A pending session is served nothing here, and neither is a request that
 * serves nobody: both are `not_found`. The session is captured when the call
 * begins, and checked before the codes are drawn and again under the identity's
 * lock, so what was proved and the sign-in it was proved on still hold when the
 * old set is replaced; a refusal leaves the old set intact. The gate is asked
 * under the lock only. A session that has changed, one the gate refuses and one
 * below the level are all refused as `not_fresh`, since the remedy is the same
 * stronger step-up.
 *
 * Only the package's own refusals become a refused result, the gate's among
 * them, since refusing by throwing is how it answers. Any other exception of a
 * seam propagates, and the event is reported outside the conversion, so a
 * listener's failure is never read as a refusal of a set that committed.
 *
 * With an identity's first additional factor a set is issued as part of the
 * change that confirms it, not through that gate: the factor's own confirmation
 * proof is what shows the session would reach the level.
 *
 * Stateless: the request and the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeIssuance
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $codes
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     */
    public function __construct(

        /** The container the configuration and the seams are resolved from. */
        private Container $container,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The set's generator. */
        private RecoveryCodeService $codes,

        /** The reader of the session's proofs. */
        private SessionFirstFactor $firstFactors,
    ) {}

    /**
     * Generate a new set for the person the request serves, and answer with its
     * codes, once, as secrets for the response, or the reason it was refused.
     *
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration
     *
     * @throws \Throwable
     */
    public function generate(): RecoveryCodeGeneration
    {
        $caller  = $this->callers->resolve(null);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::STEP_UP);

        if ($caller === null || $binding === null) {
            return RecoveryCodeGeneration::refused($caller === null ? FailureReason::NOT_FOUND : FailureReason::NOT_FRESH);
        }

        $gate = fn (?Collection $factors) => $this->assertMayIssue($binding, $factors);

        try {
            ['codes' => $codes, 'generation' => $generation] = $this->codes->replaceSet($caller->identity, $binding->application, $gate);
        } catch (OperationRefusedException $exception) {
            return self::refusedBy($exception);
        }

        $this->codes->reportGenerated($caller->identity, $binding->application, count($codes), $generation);

        return RecoveryCodeGeneration::generated($codes);
    }

    /**
     * Generate a set with the identity's first additional factor, inside the
     * change that confirms it, and return its codes, once, as secrets for the
     * response: none when the application does not accept recovery codes, the
     * session's first factor is not known, or that first factor followed by the
     * confirmation's own proof does not reach the application's level.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function withFirstFactor(MultiFactorAuthenticatable $identity, string $application, Proof $proof): array
    {
        $settings    = new ApplicationSettings($this->container->make(Repository::class), $application);
        $firstFactor = $this->firstFactors->forBinding($identity, $proof->binding);

        if (!$settings->acceptsRecoveryCodes() || $firstFactor === null) {
            return [];
        }

        $requirement = Requirement::none()->withMinimumLevel($settings->recoveryCodeLevel());

        return $this->container->make(RequirementCheck::class)->check($requirement, $firstFactor, $proof)->meetsRequirement()
            ? $this->codes->generate($identity, null, $application)
            : [];
    }

    /**
     * The refused answer of a refusal the package made; a seam's is thrown on.
     *
     * @param  \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function refusedBy(OperationRefusedException $refusal): RecoveryCodeGeneration
    {
        return $refusal->byPackage ? RecoveryCodeGeneration::refused($refusal->reason) : throw $refusal;
    }

    /**
     * Refuse issuing on a session that is no longer the one captured, that the
     * bound factor change gate does not authorise under the lock, or that does
     * not reach the level. Before the lock, with no factors, the gate is not
     * asked.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return void
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertMayIssue(ProofBinding $binding, ?Collection $factors): void
    {
        $caller = $this->callers->still(null, $binding);

        OperationRefusedException::byPackageUnless($caller !== null, FailureReason::NOT_FRESH, 'The session is no longer the one the recovery codes were asked for on.');

        if ($factors !== null) {
            $this->container->make(FactorChanges::class)->allow($caller->identity, $binding->application, $binding->sessionId, FactorChange::GENERATE_RECOVERY_CODES, $factors);
        }

        $proofs   = $this->firstFactors->proofs($caller->identity, $binding->application);
        $level    = $this->container->make(RequirementCheck::class)->check(Requirement::none(), ...$proofs)->level;
        $settings = new ApplicationSettings($this->container->make(Repository::class), $binding->application);

        OperationRefusedException::byPackageUnless(
            $level->meets($settings->recoveryCodeLevel()),
            FailureReason::NOT_FRESH,
            'The session is below the level for issuing recovery codes.',
        );
    }
}
