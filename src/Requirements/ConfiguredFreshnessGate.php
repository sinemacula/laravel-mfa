<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * The default `FreshnessGate`, which works from the proof store alone: the
 * current identity's sign-in on the current application is fresh for an
 * operation when the bound `RequirementCheck` finds its recorded proofs meet
 * the operation's requirement (see `OperationRequirements::effective()`), the
 * stricter of the application's configured one and the caller's.
 *
 * It is not fresh without an identity, without a requirement, without a sign-in
 * the store knows of, or without a first factor on it: proofs are judged only
 * after the sign-in's first factor. The first factor is the one the store
 * recorded; only when it holds none is a bound `FirstFactorResolver` asked, and
 * its answer counts only when it is a first factor of the identity on the
 * application, bound to the current sign-in, made under the identity's current
 * verification generation and not after now. Only a proof's own time counts, so
 * refreshing or regenerating the session never renews freshness.
 *
 * Stateless: the configuration, the store and every collaborator are resolved
 * on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConfiguredFreshnessGate implements FreshnessGate
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configuration, the store and the check are resolved from. */
        private Container $container,
    ) {}

    /**
     * Whether the current session is fresh for the operation.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        $application = $this->container->make(ProofService::class)->application();
        $operations  = new OperationRequirements($this->container->make(Repository::class));
        $requirement = $operations->effective($application, $operation, $callerRequirement);
        $identity    = CurrentIdentity::resolve();

        if ($requirement === null || $identity === null) {
            return false;
        }

        $proofs = $this->proofsOf($identity, $application);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs)->meetsRequirement();
    }

    /**
     * The proofs of the identity's current sign-in on the application, with the
     * first factor a bound resolver reports when the store holds none; none
     * without a sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function proofsOf(MultiFactorAuthenticatable $identity, string $application): array
    {
        $store   = $this->container->make(ProofStore::class);
        $session = $store->currentSession($identity, $application);

        if ($session === null) {
            return [];
        }

        $proofs = $store->proofs($identity, $application);

        if (self::holdsFirstFactor($proofs) || !$this->container->bound(FirstFactorResolver::class)) {
            return $proofs;
        }

        $firstFactor = $this->container->make(FirstFactorResolver::class)->resolve($identity, $application);

        return $firstFactor !== null && self::isTrusted($firstFactor, $identity, $application, $session)
            ? [$firstFactor, ...$proofs]
            : $proofs;
    }

    /**
     * Whether any of the proofs is a first factor.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return bool
     */
    private static function holdsFirstFactor(array $proofs): bool
    {
        foreach ($proofs as $proof) {
            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a resolved first factor may count for the sign-in: a first factor
     * of the identity on the application, bound to the sign-in, made under the
     * identity's current verification generation and not after now.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function isTrusted(Proof $firstFactor, MultiFactorAuthenticatable $identity, string $application, string $session): bool
    {
        return $firstFactor->kind === ProofKind::FIRST_FACTOR
            && ProofOwner::of($identity)->ownsSignIn($firstFactor->binding, $application, $session)
            && $firstFactor->generation === VerificationGeneration::current($identity)
            && $firstFactor->provedAt->lessThanOrEqualTo(CarbonImmutable::now());
    }
}
