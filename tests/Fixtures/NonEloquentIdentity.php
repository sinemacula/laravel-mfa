<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * Non-Eloquent identity fixture.
 *
 * Implements `MultiFactorAuthenticatable` without extending
 * `Illuminate\Database\Eloquent\Model`, used to exercise the manager's
 * FQCN-fallback branches in `assertFactorOwnership()`, `getCachePrefix()`, and
 * `issueBackupCodes()` — those paths only fire for identities the morph map
 * cannot resolve through `getMorphClass()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class NonEloquentIdentity implements MultiFactorAuthenticatable
{
    /**
     * Constructor.
     *
     * The configurable `$identifier` lets a single fixture exercise both the
     * normal scalar branch and the unsupported-shape branch of the manager's
     * identifier-coercion logic.
     *
     * @param  mixed  $identifier
     * @param  bool  $mfaEnabled
     * @return void
     */
    public function __construct(

        /** Auth identifier reported by the fixture. */
        private readonly mixed $identifier = 'plain-1',

        /** Whether the fixture reports MFA as enabled. */
        private readonly bool $mfaEnabled = false,

    ) {}

    /**
     * @return mixed
     */
    public function getAuthIdentifier(): mixed
    {
        return $this->identifier;
    }

    /**
     * @return string
     */
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * @return string
     */
    public function getAuthPassword(): string
    {
        return 'unused-password';
    }

    /**
     * @return string
     */
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * @return string
     */
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
    public function setRememberToken(mixed $value): void
    {
        // no-op — fixture does not persist remember tokens.
        unset($value);
    }

    /**
     * @return string
     */
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    /**
     * @return bool
     */
    public function shouldUseMultiFactor(): bool
    {
        return true;
    }

    /**
     * Always reports the configured value — non-Eloquent identities in these
     * tests have no real factor store, so the boolean is held directly to keep
     * the cached `isSetup()` path testable without touching a builder.
     *
     * @return bool
     */
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
    public function authFactors(): Builder
    {
        // @phpstan-ignore staticMethod.dynamicCall (newQuery is an instance method on Eloquent\Model)
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
