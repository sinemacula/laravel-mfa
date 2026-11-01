<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * Composes what an identity's sign-in must prove, and asks whether the current
 * session is fresh enough for a named operation.
 *
 * A sign-in's requirement is the strictest of its parts, so the same inputs
 * always give the same answer in any order:
 *
 * - the application's configured mode: nothing for `never` (and for an
 *   application nobody configured), an additional verification for `always`,
 *   and for `enrolled` an additional verification once the identity has a
 *   confirmed factor;
 * - the identity's own requirement, from the bound `IdentityRequirement`;
 * - an additional verification while the identity's re-enrolment obligation is
 *   set, in every application (see `ReenrollmentObligation`);
 * - where a tenant is active, the tenant's requirement, from the bound
 *   `TenantRequirement`. It is not part of the sign-in's own requirement, which
 *   is asked before any principal is chosen.
 *
 * A step-up adds the operation's requirement, which the bound `FreshnessGate`
 * judges. This package's own setting for the operation is passed to the gate as
 * part of the caller's requirement, so a gate an adapter binds over an
 * authentication layer always receives it and applies the stricter of it and
 * its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the configuration and the seams are read from. */
        private Container $container,
    ) {}

    /**
     * The requirement the current identity's sign-in on the current application
     * must meet: none without an MFA-capable identity.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function requirement(): Requirement
    {
        $identity = CurrentIdentity::resolve();

        if ($identity === null) {
            return Requirement::none();
        }

        return $this->requirementFor($identity, $this->container->make(ProofService::class)->application());
    }

    /**
     * The requirement the identity's sign-in on the application must meet: the
     * strictest of the application's, the identity's and the re-enrolment
     * obligation's, and the active tenant's when one is given.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  ?string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, ?string $tenant = null): Requirement
    {
        $parts = [
            $this->applicationPart($identity, $application),
            $this->container->make(IdentityRequirement::class)->requirementFor($identity, $application),
            self::additionalVerificationWhen(ReenrollmentObligation::isRequired($identity)),
        ];

        if ($tenant !== null) {
            $parts[] = $this->container->make(TenantRequirement::class)->requirementFor($identity, $application, $tenant);
        }

        return Requirement::strictest(...$parts);
    }

    /**
     * Whether the current session is fresh enough for the operation, asked of
     * the bound `FreshnessGate` with the strictest of this package's setting
     * for the operation and the caller's requirement. A name that is not an
     * operation's is never fresh; a caller's requirement that asks for nothing
     * adds nothing, and one with a part that carries no maximum age, or one
     * longer than a day, is refused.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function isFresh(string $operation, ?Requirement $requirement = null): bool
    {
        $application = $this->container->make(ProofService::class)->application();
        $caller      = (new OperationRequirements($this->config()))->effective($application, $operation, $requirement);

        if (!Operation::isName($operation)) {
            return false;
        }

        return $this->container->make(FreshnessGate::class)->isFresh($operation, $caller);
    }

    /**
     * What the application's configured mode requires of the identity's
     * sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function applicationPart(MultiFactorAuthenticatable $identity, string $application): Requirement
    {
        return self::additionalVerificationWhen(match ((new ApplicationSettings($this->config(), $application))->requirement()) {
            RequirementMode::NEVER    => false,
            RequirementMode::ENROLLED => $identity->isMfaEnabled(),
            RequirementMode::ALWAYS   => true,
        });
    }

    /**
     * An additional verification of any age when the condition holds, nothing
     * otherwise.
     *
     * @param  bool  $condition
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \InvalidArgumentException
     */
    private static function additionalVerificationWhen(bool $condition): Requirement
    {
        return $condition ? Requirement::none()->withAdditionalVerification() : Requirement::none();
    }

    /**
     * The configuration the settings are read from.
     *
     * @return \Illuminate\Contracts\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function config(): Repository
    {
        return $this->container->make(Repository::class);
    }
}
