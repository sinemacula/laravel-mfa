<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Laravel\Sanctum\HasApiTokens;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * Test user model used across the MFA test suites.
 *
 * Implements `MultiFactorAuthenticatable` and Laravel's standard
 * `Authenticatable` contract. MFA preference is controlled via the
 * `mfa_enabled` boolean column so individual tests can flip it
 * without reaching into mocks or stubs.
 *
 * @property int $id
 * @property bool $mfa_enabled
 * @property ?string $email
 */
class TestUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait, HasApiTokens;

    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
        'mfa_enabled',
    ];

    /** @var array<string, string> */
    protected $casts = [
        'mfa_enabled' => 'boolean',
    ];

    /**
     * Determine whether MFA should be applied for this test user.
     *
     * @return bool
     */
    public function shouldUseMultiFactor(): bool
    {
        return (bool) $this->getAttribute('mfa_enabled');
    }

    /**
     * Determine whether the user has any verified factor.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool
    {
        return self::countFactors($this->authFactors()) > 0;
    }

    /**
     * Return the MFA factor builder scoped to this user.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder
    {
        $builder = $this->factors()->getQuery();

        return self::coerceFactorBuilder($builder);
    }

    /**
     * Polymorphic `factors` relation.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Mfa\Models\Factor, $this>
     */
    public function factors(): MorphMany
    {
        return $this->morphMany(Factor::class, 'authenticatable');
    }

    /**
     * Re-present the morph-relation builder under the intersection type
     * required by the `MultiFactorAuthenticatable` contract. The shipped
     * Factor model IS both an Eloquent Model and the Factor contract, so
     * the cast is sound; this helper hides the generic-invariance gap
     * from PHPStan.
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

    /**
     * Wrap the dynamic count() call so PHPStan does not flag it as a
     * dynamic call to a static method.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>  $builder
     * @return int
     *
     * @formatter:on
     */
    private static function countFactors(Builder $builder): int
    {
        return $builder->toBase()->count();
    }
}
