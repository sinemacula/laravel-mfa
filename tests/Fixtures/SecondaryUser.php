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

/**
 * A second `MultiFactorAuthenticatable` Eloquent model used to assert
 * that the package's polymorphic factor relation works against more
 * than one identity class within the same application.
 *
 * Mirrors `TestUser` but lives on its own table so polymorphic factor
 * lookup must scope by `authenticatable_type` correctly.
 *
 * @property int $id
 * @property bool $mfa_enabled
 * @property ?string $email
 */
class SecondaryUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait;

    /** @var string */
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

    public function shouldUseMultiFactor(): bool
    {
        return (bool) $this->getAttribute('mfa_enabled');
    }

    public function isMfaEnabled(): bool
    {
        return $this->authFactors()->exists();
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
        return $this->factors()->getQuery();
    }

    /**
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Mfa\Models\Factor, $this>
     */
    public function factors(): MorphMany
    {
        return $this->morphMany(Factor::class, 'authenticatable');
    }
}
