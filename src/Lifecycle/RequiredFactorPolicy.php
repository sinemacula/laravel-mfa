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
 * While a factor is required, refuses removing the last one some application
 * accepts, so required MFA cannot be turned off by the person it applies to.
 * Takes no lock, so it can be asked before the identity's lock and under it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequiredFactorPolicy implements LastFactorPolicy
{
    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     */
    public function __construct(

        /** Read on every call so a changed application applies. */
        private Repository $config,

        /** The identity requirement is resolved on every call. */
        private Container $container,

        /** A passkey factor is usable only with its association. */
        private PasskeyAssociations $associations,
    ) {}

    /**
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
     * Required by the bound identity requirement or any application that always
     * requires a factor.
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
