<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * An identity that is not an Eloquent model, so its type falls back to the
 * class name where the morph map cannot name it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NonEloquentIdentity implements MultiFactorAuthenticatable
{
    /**
     * @param  mixed  $identifier
     * @param  bool  $mfaEnabled
     * @param  bool  $person
     * @param  bool  $active
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return void
     */
    public function __construct(

        /** Any shape, to reach the unsupported-identifier branches. */
        private readonly mixed $identifier = 'plain-1',

        /** @var bool */
        private readonly bool $mfaEnabled = false,

        /** Whether it is a person, who may hold factors. */
        private readonly bool $person = true,

        /** @var bool */
        private readonly bool $active = true,

        /** What it requires of its own sign-ins. */
        private readonly ?Requirement $requirement = null,
    ) {}

    /**
     * @return bool
     */
    #[\Override]
    public function canHoldFactors(): bool
    {
        return $this->person;
    }

    /**
     * @return bool
     */
    #[\Override]
    public function isMfaActive(): bool
    {
        return $this->active;
    }

    /**
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requiresAdditionalFactor(): ?Requirement
    {
        return $this->requirement;
    }

    /**
     * @return mixed
     */
    #[\Override]
    public function getAuthIdentifier(): mixed
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        return 'unused-password';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * Typed `mixed` because the contract leaves the parameter untyped.
     *
     * @param  mixed  $value
     * @return void
     */
    #[\Override]
    public function setRememberToken(mixed $value): void
    {
        // Remember tokens are not kept.
        unset($value);
    }

    /**
     * @return string
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    /**
     * Held directly, since there is no factor store behind it.
     *
     * @return bool
     */
    #[\Override]
    public function isMfaEnabled(): bool
    {
        return $this->mfaEnabled;
    }

    /**
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
     * Narrows the builder to the type the contract requires.
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
