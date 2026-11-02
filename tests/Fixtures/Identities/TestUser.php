<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Laravel\Sanctum\HasApiTokens;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * Test user model used across the MFA test suites.
 *
 * Implements `MultiFactorAuthenticatable` and Laravel's standard
 * `Authenticatable` contract. Whether the user requires an additional
 * verification of its own sign-ins is controlled via the `mfa_enabled` boolean
 * column so individual tests can flip it without reaching into mocks or stubs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property bool $mfa_enabled
 * @property ?string $email
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
final class TestUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait, HasApiTokens, HasFactors;

    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
        'mfa_enabled',
    ];

    /**
     * Require an additional verification of every sign-in while the
     * `mfa_enabled` column is set, and nothing of the user's own otherwise.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requiresAdditionalFactor(): ?Requirement
    {
        return (bool) $this->getAttribute('mfa_enabled') ? Requirement::none()->withAdditionalVerification() : null;
    }

    /**
     * Determine whether the user has any factor at all, whatever its status:
     * looser than the trait's confirmed-only rule, so the fixture's existing
     * flows read a freshly created factor as enabled.
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
        return WriteConnection::query($builder)->toBase()->count();
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
