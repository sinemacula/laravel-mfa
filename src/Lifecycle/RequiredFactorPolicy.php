<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\LastFactorPolicy;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The default `LastFactorPolicy`: required MFA cannot be turned off by the
 * person it applies to.
 *
 * While the identity's own contract requires an additional factor, or any
 * configured application always requires one, a factor may be removed only when
 * another remains that some configured application accepts: confirmed, of a
 * type an application enables, and, for a passkey, with an association that
 * matches it (see `Passkeys\PasskeyAssociations`). "Last" means the last
 * acceptable one, not the last row, so a pending factor, one of a type no
 * application enables, or a passkey that is unusable for want of its
 * association does not keep the identity covered. Without such a requirement
 * any factor may be removed. It knows nothing of tenants; an adapter rebinds it
 * to consult a tenant's policy as well.
 *
 * The identity's factors are read from the write connection with a locking
 * read, so asked again inside the removal's factor state transaction it sees
 * what the lock holds.
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
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     */
    public function __construct(

        /** The configuration the applications are read from on every call. */
        private Repository $config,

        /** The association records a passkey factor is usable only with. */
        private PasskeyAssociations $associations,
    ) {}

    /**
     * Whether the factor may be removed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    #[\Override]
    public function allowsRemoval(MultiFactorAuthenticatable $identity, string $application, Factor $factor): bool
    {
        if (!$this->isRequired($identity)) {
            return true;
        }

        $removed = LockedFactors::idOf($factor);
        $types   = $this->enabledTypes();
        $owner   = ProofOwner::of($identity);

        $factors = WriteConnection::query($identity->authFactors())->lockForUpdate()->get();

        return $factors->contains(fn (Factor&Model $other): bool => LockedFactors::idOf($other) !== $removed
            && $other->isConfirmed()
            && in_array($other->getType(), $types, true)
            && ($other->getType() !== PasskeyAssertions::TYPE || $this->associations->associates($other, $owner)));
    }

    /**
     * Whether a factor is required of the identity: by its own contract, or by
     * any configured application that always requires one.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isRequired(MultiFactorAuthenticatable $identity): bool
    {
        $own = $identity->requiresAdditionalFactor();

        if ($own !== null && !$own->isEmpty()) {
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
