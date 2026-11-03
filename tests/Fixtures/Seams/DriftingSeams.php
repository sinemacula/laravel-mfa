<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Faulty seams whose fault only shows over more than one call, or against a
 * person, for proving the contract kit rejects them: a resolver that names a
 * new, never blank, application each time it is asked; a requirement that
 * answers a question the same each time it is asked in a row, but by the one
 * asked before it; and a resolver that finds nobody a person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DriftingSeams implements ApplicationResolver, IdentityRequirement, SubjectTypeResolver
{
    /** @var int How often an application has been named. */
    private int $named = 0;

    /** @var ?string The application the requirement was last asked about. */
    private ?string $lastAsked = null;

    /**
     * A new application each time.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return 'application-' . ++$this->named;
    }

    /**
     * Multifactor when the question asked before was about another application,
     * nothing otherwise.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  ?string  $tenant
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(MultiFactorAuthenticatable $identity, string $application, ?string $tenant = null): Requirement
    {
        $changed         = $this->lastAsked !== null && $this->lastAsked !== $application;
        $this->lastAsked = $application;

        return $changed ? Requirement::none()->withMultifactor() : Requirement::none();
    }

    /**
     * Nobody is a person.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isPerson(Authenticatable $identity): bool
    {
        return false;
    }
}
