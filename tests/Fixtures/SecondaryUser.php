<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * A second `MultiFactorAuthenticatable` Eloquent model used to assert
 * that the package's polymorphic factor relation works against more
 * than one identity class within the same application.
 *
 * Mirrors `TestUser` but lives on its own table so polymorphic factor
 * lookup must scope by `authenticatable_type` correctly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property int $id
 * @property bool $mfa_enabled
 * @property ?string $email
 */
class SecondaryUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait;

    /** @var string|null */
    protected $table = 'test_secondary_users';

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
     * Opt the identity into MFA enforcement based on the test fixture
     * column.
     *
     * @return bool
     */
    public function shouldUseMultiFactor(): bool
    {
        return (bool) $this->getAttribute('mfa_enabled');
    }

    /**
     * Report whether the identity has at least one persisted factor.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool
    {
        return self::countFactors($this->authFactors()) > 0;
    }

    /**
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\Factor>
     *
     * @formatter:on
     */
    public function authFactors(): Builder
    {
        return self::coerceFactorBuilder($this->factors()->getQuery());
    }

    /**
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Mfa\Models\Factor, $this>
     */
    public function factors(): MorphMany
    {
        return $this->morphMany(Factor::class, 'authenticatable');
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
