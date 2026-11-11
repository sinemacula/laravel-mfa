<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\RequirementMode;

/**
 * Composes a sign-in's requirement, the strictest of its parts so order never
 * matters, and asks the bound `FreshnessGate` about freshness.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequirementService
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams and configuration are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * None without an identity, and none for a pending session.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function requirement(CallerContext $caller): Requirement
    {
        $identity = $caller->identity;

        if ($identity === null || $caller->pending !== null) {
            return Requirement::none();
        }

        return $this->requirementFor($identity, $caller->application);
    }

    /**
     * The strictest of the application's mode, the identity's own, the
     * re-enrolment obligation's and the active tenant's.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application): Requirement
    {
        $parts = [
            $this->applicationPart($identity, $application),
            $this->container->make(IdentityRequirement::class)->requirementFor($identity, $application),
            self::additionalVerificationWhen(ReenrollmentObligation::isRequired($identity)),
        ];

        $tenant = $this->container->make(ActiveTenantResolver::class)->activeTenant($identity, $application);

        if ($tenant !== null) {
            $parts[] = $this->container->make(TenantRequirement::class)->requirementFor($identity, $application, $tenant);
        }

        return Requirement::strictest(...$parts);
    }

    /**
     * A name that is not an operation's is never fresh and never throws.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function isFresh(CallerContext $caller, string $operation, ?Requirement $requirement = null): bool
    {
        if (!Operation::isName($operation)) {
            return false;
        }

        return $this->container->make(FreshnessGate::class)->isFresh($caller, $operation, $this->effective($caller, $operation, $requirement));
    }

    /**
     * `null` when not fresh or the gate cannot say.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function freshUntil(CallerContext $caller, string $operation, ?Requirement $requirement = null): ?CarbonImmutable
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        return $this->container->make(FreshnessGate::class)->freshUntil($caller, $operation, $this->effective($caller, $operation, $requirement));
    }

    /**
     * The requirement the bound gate holds the session to, or `null` with none
     * or for a name that is not an operation's.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function freshnessRequirement(CallerContext $caller, string $operation, ?Requirement $requirement = null): ?Requirement
    {
        if (!Operation::isName($operation)) {
            return null;
        }

        return $this->container->make(FreshnessGate::class)->requirement($caller, $operation, $this->effective($caller, $operation, $requirement));
    }

    /**
     * The package's setting is passed within the caller's requirement, so a
     * bound gate always applies it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function effective(CallerContext $caller, string $operation, ?Requirement $requirement): ?Requirement
    {
        return (new OperationRequirements($this->config()))->effective($caller->application, $operation, $requirement);
    }

    /**
     * What the application's configured mode requires of the sign-in.
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
     * An additional verification of any age, or nothing.
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
     * @return \Illuminate\Contracts\Config\Repository
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function config(): Repository
    {
        return $this->container->make(Repository::class);
    }
}
