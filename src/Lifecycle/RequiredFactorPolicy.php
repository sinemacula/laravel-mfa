<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The default `LastFactorPolicy`: required MFA cannot be turned off by the
 * person it applies to.
 *
 * While the bound `IdentityRequirement` requires something of the identity, or
 * any configured application always requires a factor, a factor may be removed
 * only when another remains that some configured application accepts:
 * confirmed, not disabled at the failure ceiling, of a type an application
 * enables, and, for a passkey, with an association that matches it (see
 * `Passkeys\PasskeyAssociations`). "Last" means the last acceptable one, not
 * the last row, so a pending factor, a disabled one, one of a type no
 * application enables, or a passkey that is unusable for want of its
 * association does not keep the identity covered; and an identity's only factor
 * stays even when it is itself unusable. Without such a requirement any factor
 * may be removed. It knows nothing of tenants; an adapter rebinds it to consult
 * a tenant's policy as well.
 *
 * It decides on the factors the caller gives it and takes no lock, so it can be
 * asked before the identity's lock is held and again under it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequiredFactorPolicy implements LastFactorPolicy
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     */
    public function __construct(

        /** The configuration the applications are read from on every call. */
        private Repository $config,

        /** The container the identity's requirement is resolved from on every call. */
        private Container $container,

        /** The association records a passkey factor is usable only with. */
        private PasskeyAssociations $associations,
    ) {}

    /**
     * Whether the factor may be removed, on the factors given.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return bool
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function allowsRemoval(MultiFactorAuthenticatable $identity, string $application, Factor $factor, Collection $factors): bool
    {
        if (!$this->isRequired($identity, $application)) {
            return true;
        }

        $removed = LockedFactors::idOf($factor);
        $types   = $this->enabledTypes();
        $owner   = ProofOwner::of($identity);

        return $factors->contains(fn (EloquentFactor&Model $other): bool => LockedFactors::idOf($other) !== $removed && $this->covers($other, $types, $owner));
    }

    /**
     * Whether the factor keeps a required factor covered: confirmed, not
     * disabled at the failure ceiling, of a type some application enables, and,
     * for a passkey, still associated with the owner.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  list<string>  $types
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return bool
     */
    private function covers(EloquentFactor&Model $factor, array $types, ProofOwner $owner): bool
    {
        if (!$factor->isConfirmed() || $factor->getDisabledAt() !== null) {
            return false;
        }

        if (!in_array($factor->getType(), $types, true)) {
            return false;
        }

        return $factor->getType() !== PasskeyAssertions::TYPE || $this->associations->associates($factor, $owner);
    }

    /**
     * Whether a factor is required of the identity: by the bound identity
     * requirement, or by any configured application that always requires one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function isRequired(MultiFactorAuthenticatable $identity, string $application): bool
    {
        if (!$this->container->make(IdentityRequirement::class)->requirementFor($identity, $application)->isEmpty()) {
            return true;
        }

        foreach (ApplicationSettings::names($this->config) as $name) {
            if ((new ApplicationSettings($this->config, $name))->requirement() === RequirementMode::ALWAYS) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every factor type any configured application enables.
     *
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    private function enabledTypes(): array
    {
        $types = [];

        foreach (ApplicationSettings::names($this->config) as $name) {
            $types = [...$types, ...(new ApplicationSettings($this->config, $name))->types()];
        }

        return array_values(array_unique($types));
    }
}
