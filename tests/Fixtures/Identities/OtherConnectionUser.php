<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * An identity on a named connection of its own, `identities`, other than the
 * default one and the storage connection, as an application whose users live in
 * another database has.
 *
 * Mirrors `TestUser`, reading the same `test_users` columns from the
 * `identities` connection, so a test can prove its factors are still read and
 * written on the storage connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property bool $mfa_enabled
 * @property ?string $email
 */
final class OtherConnectionUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait;

    /** @var string|\UnitEnum|null */
    protected $connection = 'identities';

    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
        'mfa_enabled',
    ];

    /**
     * Determine whether MFA should be applied for this user.
     *
     * @return bool
     */
    #[\Override]
    public function shouldUseMultiFactor(): bool
    {
        return (bool) $this->getAttribute('mfa_enabled');
    }

    /**
     * Determine whether the user has at least one enrolled factor.
     *
     * @return bool
     */
    #[\Override]
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
    #[\Override]
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
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'mfa_enabled' => 'boolean',
        ];
    }

    /**
     * Wrap the dynamic count() call so PHPStan does not flag it as a dynamic
     * call to a static method.
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

    /**
     * Re-present the morph-relation builder under the intersection type
     * required by the `MultiFactorAuthenticatable` contract. The shipped Factor
     * model IS both an Eloquent Model and the Factor contract, so the cast is
     * sound; this helper hides the generic-invariance gap from PHPStan.
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
