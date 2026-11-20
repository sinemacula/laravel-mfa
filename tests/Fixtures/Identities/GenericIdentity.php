<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * An identity that is not an Eloquent model, written as the identity models
 * guide shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GenericIdentity extends GenericUser implements MultiFactorAuthenticatable
{
    /**
     * @param  int|string  $id
     */
    public function __construct(

        /** @var int|string */
        private readonly int|string $id,
    ) {
        parent::__construct(['id' => $id]);
    }

    /**
     * @return int|string
     */
    #[\Override]
    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    /**
     * @return bool
     */
    #[\Override]
    public function canHoldFactors(): bool
    {
        return true;
    }

    /**
     * @return bool
     */
    #[\Override]
    public function isMfaActive(): bool
    {
        return true;
    }

    /**
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requiresAdditionalFactor(): ?Requirement
    {
        return null;
    }

    /**
     * @return bool
     */
    #[\Override]
    public function isMfaEnabled(): bool
    {
        return $this->authFactors()->toBase()->pluck('status')->contains(static fn (mixed $status): bool => $status !== 'pending');
    }

    /**
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
     *
     * @formatter:on
     */
    #[\Override]
    public function authFactors(): Builder
    {
        $builder = Factor::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getAuthIdentifier());

        return self::coerceFactorBuilder($builder);
    }

    /**
     * Narrows the builder to the type the contract requires.
     *
     * @formatter:off
     *
     * @param  mixed  $builder
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>
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

        /** @var \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> $builder */
        return $builder;
    }
}
