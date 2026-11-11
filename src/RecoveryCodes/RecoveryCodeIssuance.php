<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
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
 * Issues a new recovery code set on a session the `Contracts\FactorChangeGate`
 * authorises and that reaches the application's level for issuing them.
 *
 * The session is rechecked under the identity's lock so a refusal leaves the
 * old set intact; every refusal is `not_fresh` because the remedy is the same
 * step-up. The event is reported outside the refusal conversion so a listener's
 * failure is never read as a refusal of a committed set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeIssuance
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService  $codes
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     */
    public function __construct(

        /** Seams and configuration are resolved per call. */
        private Container $container,

        /** Resolves who the request serves. */
        private CallerContextResolver $callers,

        /** Generates the set. */
        private RecoveryCodeService $codes,

        /** Reads the session's proofs. */
        private SessionFirstFactor $firstFactors,
    ) {}

    /**
     * A pending session or a request serving nobody is refused as `not_found`.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGeneration
     *
     * @throws \Throwable
     */
    public function generate(CallerContext $context): RecoveryCodeGeneration
    {
        $caller  = $this->callers->resolve($context, null);
        $binding = $caller === null ? null : $this->callers->binding($caller, Purpose::STEP_UP);

        if ($caller === null || $binding === null) {
            return RecoveryCodeGeneration::refused($caller === null ? FailureReason::NOT_FOUND : FailureReason::NOT_FRESH);
        }

        $gate = fn (?Collection $factors) => $this->assertMayIssue($caller, $binding, $factors);

        try {
            ['codes' => $codes, 'generation' => $generation] = $this->codes->replaceSet($caller->identity, $binding->application, $gate);
        } catch (OperationRefusedException $exception) {
            return self::refusedBy($exception);
        }

        $this->codes->reportGenerated($caller->identity, $binding->application, count($codes), $generation, null, $caller->client, $binding->sessionId);

        return RecoveryCodeGeneration::generated($codes);
    }

    /**
     * Issue a set inside the change confirming the first additional factor,
     * bypassing the gate since the confirmation proof shows the level; empty
     * when the application or level does not allow one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function withFirstFactor(MultiFactorAuthenticatable $identity, string $application, Proof $proof, ?PendingContext $pending, ?ClientContext $client = null): array
    {
        $settings    = new ApplicationSettings($this->container->make(Repository::class), $application);
        $firstFactor = $this->firstFactors->forBinding($identity, $proof->binding, $pending);

        if (!$settings->acceptsRecoveryCodes() || $firstFactor === null) {
            return [];
        }

        $requirement = Requirement::none()->withMinimumLevel($settings->recoveryCodeLevel());

        return $this->container->make(RequirementCheck::class)->check($requirement, $firstFactor, $proof)->meetsRequirement()
            ? $this->codes->generate($identity, $application, client: $client, signInId: $proof->binding->sessionId)
            : [];
    }

    /**
     * Rethrow a seam's refusal; only the package's own become a refused result.
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
     * The gate is asked only under the lock, when factors are given.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
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
    private function assertMayIssue(Caller $served, ProofBinding $binding, ?Collection $factors): void
    {
        $caller = $this->callers->still($served, null, $binding);

        OperationRefusedException::byPackageUnless($caller !== null, FailureReason::NOT_FRESH, 'The session is no longer the one the recovery codes were asked for on.');

        if ($factors !== null) {
            $this->container->make(FactorChanges::class)->allow($caller->identity, $binding->application, $binding->sessionId, FactorChange::GENERATE_RECOVERY_CODES, $factors);
        }

        $proofs   = $this->firstFactors->proofsOf($caller->identity, $binding->application, $binding->sessionId);
        $level    = $this->container->make(RequirementCheck::class)->check(Requirement::none(), ...$proofs)->level;
        $settings = new ApplicationSettings($this->container->make(Repository::class), $binding->application);

        OperationRefusedException::byPackageUnless(
            $level->meets($settings->recoveryCodeLevel()),
            FailureReason::NOT_FRESH,
            'The session is below the level for issuing recovery codes.',
        );
    }
}
