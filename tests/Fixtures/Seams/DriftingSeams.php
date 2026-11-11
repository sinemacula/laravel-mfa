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
 * person, for proving the contract kit rejects them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DriftingSeams implements ApplicationResolver, IdentityRequirement, SubjectTypeResolver
{
    /** @var int */
    private int $named = 0;

    /** @var ?string */
    private ?string $lastAsked = null;

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        return 'application-' . ++$this->named;
    }

    /**
     * Multifactor only when the previous call named another application.
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
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     */
    #[\Override]
    public function isPerson(Authenticatable $identity): bool
    {
        return false;
    }
}
