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
    use AuthenticatableTrait;

    /** @var string */
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
        return $this->authFactors()->exists();
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
        return $this->factors()->getQuery();
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
}
