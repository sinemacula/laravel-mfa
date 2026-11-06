<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * Non-Eloquent identity fixture.
 *
 * Implements `MultiFactorAuthenticatable` without extending
 * `Illuminate\Database\Eloquent\Model`, used to exercise the FQCN-fallback
 * branch of `Support\IdentityType::of()` that the proof store and recovery
 * codes rely on — that path only fires for identities the morph map cannot
 * resolve through `getMorphClass()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NonEloquentIdentity implements MultiFactorAuthenticatable
{
    /**
     * Constructor.
     *
     * The configurable `$identifier` lets a single fixture exercise both the
     * normal scalar branch and the unsupported-shape branch of what reads the
     * identity's key.
     *
     * @param  mixed  $identifier
     * @param  bool  $mfaEnabled
     * @param  bool  $person
     * @param  bool  $active
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return void
     */
    public function __construct(

        /** Auth identifier reported by the fixture. */
        private readonly mixed $identifier = 'plain-1',

        /** Whether the fixture reports MFA as enabled. */
        private readonly bool $mfaEnabled = false,

        /** Whether the fixture is a person, who may hold factors. */
        private readonly bool $person = true,

        /** Whether the fixture is active. */
        private readonly bool $active = true,

        /** What the fixture requires of its own sign-ins. */
        private readonly ?Requirement $requirement = null,
    ) {}

    /**
     * Report whether the fixture is a person.
     *
     * @return bool
     */
    #[\Override]
    public function canHoldFactors(): bool
    {
        return $this->person;
    }

    /**
     * Report whether the fixture is active.
     *
     * @return bool
     */
    #[\Override]
    public function isMfaActive(): bool
    {
        return $this->active;
    }

    /**
     * Report what the fixture requires of its own sign-ins.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requiresAdditionalFactor(): ?Requirement
    {
        return $this->requirement;
    }

    /**
     * Return the fixture's seeded auth identifier.
     *
     * @return mixed
     */
    #[\Override]
    public function getAuthIdentifier(): mixed
    {
        return $this->identifier;
    }

    /**
     * Return the conventional auth-identifier column name.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Return a placeholder password — the fixture does not authenticate.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        return 'unused-password';
    }

    /**
     * Return the conventional password column name.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * Return an empty remember token — the fixture has no persistent session.
     *
     * @return string
     */
    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * The upstream `Authenticatable` contract declares this parameter untyped
     * (its signature `setRememberToken($value)` accepts any value); the
     * implementation widens to `mixed` so the LSP rule stays satisfied without
     * losing the static-analysis type signal.
     *
     * @param  mixed  $value
     * @return void
     */
    #[\Override]
    public function setRememberToken(mixed $value): void
    {
        // no-op — fixture does not persist remember tokens.
        unset($value);
    }

    /**
     * Return the conventional remember-token column name.
     *
     * @return string
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    /**
     * Always reports the configured value — non-Eloquent identities in these
     * tests have no real factor store, so the boolean is held directly and
     * nothing touches a builder.
     *
     * @return bool
     */
    #[\Override]
    public function isMfaEnabled(): bool
    {
        return $this->mfaEnabled;
    }

    /**
     * Return a builder against the shipped Factor model — the manager only
     * invokes this when `isMfaEnabled()` is true, which the default fixture
     * configuration avoids.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    #[\Override]
    public function authFactors(): Builder
    {
        // @phpstan-ignore staticMethod.dynamicCall
        $builder = (new Factor)->newQuery();

        return self::coerceFactorBuilder($builder);
    }

    /**
     * Re-present the morph-relation builder under the intersection type
     * required by the `MultiFactorAuthenticatable` contract.
     *
     * @formatter:off
     *
     * @param  mixed  $builder
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @throws \Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException
     *
     * @formatter:on
     */
    private static function coerceFactorBuilder(mixed $builder): Builder
    {
        if (!$builder instanceof Builder) {
            throw new UnexpectedBuilderTypeException('Expected an Eloquent Builder instance.');
        }

        /** @var \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor> $builder */
        return $builder;
    }
}
