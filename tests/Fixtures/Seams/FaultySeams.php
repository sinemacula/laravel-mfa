<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * One faulty implementation of each of several seams, for proving the contract
 * kit rejects them: a revoker that revokes nothing, a transition that fails
 * with an `Error`, a gate that finds everything fresh, requirements that change
 * with every call, a resolver that names a blank application, and one that
 * finds everyone a person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FaultySeams implements ApplicationResolver, FreshnessGate, IdentityRequirement, SessionRevoker, SessionTransition, SubjectTypeResolver, TenantRequirement
{
    /** @var int How often a requirement has been asked. */
    private int $asked = 0;

    /**
     * A blank application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return ' ';
    }

    /**
     * Everything is fresh.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return bool
     */
    #[\Override]
    public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
    {
        return true;
    }

    /**
     * A deadline already past, however fresh it says the session is.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return \Carbon\CarbonImmutable
     */
    #[\Override]
    public function freshUntil(string $operation, ?Requirement $callerRequirement = null): CarbonImmutable
    {
        return CarbonImmutable::now()->subHour();
    }

    /**
     * A requirement that asks for nothing, whatever the operation or the caller
     * asks.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirement(string $operation, ?Requirement $callerRequirement = null): Requirement
    {
        return Requirement::none();
    }

    /**
     * A requirement that changes with every call.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  ?string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, ?string $tenant = null): Requirement
    {
        return ++$this->asked % 2 === 0 ? Requirement::none()->withMultifactor() : Requirement::none();
    }

    /**
     * Revoke nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $session): RemovalRevocation
    {
        // A faulty revoker revokes nothing.
        return RemovalRevocation::othersEnded();
    }

    /**
     * Revoke nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        // A faulty revoker revokes nothing.
    }

    /**
     * Fail with an error rather than a refusal.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     * @return void
     *
     * @throws \LogicException
     */
    #[\Override]
    public function returnToPending(MultiFactorAuthenticatable $identity, string $application, Requirement $outstanding): void
    {
        throw new \LogicException('A faulty transition fails without refusing.');
    }

    /**
     * Everyone is a person.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isPerson(Authenticatable $identity): bool
    {
        return true;
    }
}
