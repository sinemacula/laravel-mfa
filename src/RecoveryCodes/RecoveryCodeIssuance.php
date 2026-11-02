<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;

/**
 * Issues a new recovery code set to the person the request serves, only on a
 * session fresh enough for `mfa.generate_recovery_codes` that also reaches the
 * level the application sets for issuing them.
 *
 * A pending session is served nothing here, and neither is a request that
 * serves nobody. The session is captured when the call begins, and checked
 * before the codes are drawn and again under the identity's lock, so what was
 * proved and the sign-in it was proved on still hold when the old set is
 * replaced; a refusal leaves the old set intact. A session that has changed,
 * one that is not fresh and one below the level are all refused as `not_fresh`,
 * since the remedy is the same stronger step-up.
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
     * Generate a new set for the person the request serves, and return its
     * codes, once, as secrets for the response; none without a person signed
     * in, or on a pending session.
     *
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function generate(): array
    {
        $caller = $this->callers->resolve(null);

        if ($caller === null) {
            return [];
        }

        $binding = $this->callers->binding($caller, Purpose::STEP_UP);

        OperationRefusedException::unless($binding !== null, FailureReason::NOT_FRESH, 'The identity has no sign-in to issue recovery codes on.');

        return $this->codes->generate($caller->identity, null, $binding->application, fn () => $this->assertMayIssue($binding));
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
     * Refuse issuing on a session that is no longer the one captured, is not
     * fresh enough for the operation, or does not reach the level.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function assertMayIssue(ProofBinding $binding): void
    {
        $caller = $this->callers->still(null, $binding);

        OperationRefusedException::unless($caller !== null, FailureReason::NOT_FRESH, 'The session is no longer the one the recovery codes were asked for on.');

        $fresh = $this->container->make(RequirementService::class)->isFresh(Operation::GENERATE_RECOVERY_CODES->value);

        OperationRefusedException::unless($fresh, FailureReason::NOT_FRESH, 'The session is not fresh enough to issue recovery codes.');

        $proofs   = $this->firstFactors->proofs($caller->identity, $binding->application);
        $level    = $this->container->make(RequirementCheck::class)->check(Requirement::none(), ...$proofs)->level;
        $settings = new ApplicationSettings($this->container->make(Repository::class), $binding->application);

        OperationRefusedException::unless($level->meets($settings->recoveryCodeLevel()), FailureReason::NOT_FRESH, 'The session is below the level for issuing recovery codes.');
    }
}
