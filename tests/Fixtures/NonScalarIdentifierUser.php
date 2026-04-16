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
 * MultiFactorAuthenticatable whose `getAuthIdentifier()` returns an
 * object rather than a scalar, used to exercise the manager's
 * non-scalar auth-identifier fallback branch in `getCachePrefix()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class NonScalarIdentifierUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait;

    /** @var string */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
        'mfa_enabled',
    ];

    /**
     * Return a non-scalar auth identifier to exercise the fallback
     * branch of the manager's `getCachePrefix()` helper.
     *
     * @return mixed
     */
    #[\Override]
    public function getAuthIdentifier(): mixed
    {
        return (object) ['id' => 1];
    }

    /**
     * Always opts into MFA for test purposes.
     *
     * @return bool
     */
    public function shouldUseMultiFactor(): bool
    {
        return true;
    }

    /**
     * Does not have any factors for the purposes of these tests.
     *
     * @return bool
     */
    public function isMfaEnabled(): bool
    {
        return false;
    }

    /**
     * Return an empty factor builder (no factors expected).
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
