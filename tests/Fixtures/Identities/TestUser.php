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
 * The suite's identity model; `mfa_enabled` sets whether its sign-ins need an
 * additional verification.
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
     * Additional verification of every sign-in while `mfa_enabled` is set.
     *
     * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    #[\Override]
    public function requiresAdditionalFactor(): ?Requirement
    {
        return (bool) $this->getAttribute('mfa_enabled') ? Requirement::none()->withAdditionalVerification() : null;
    }

    /**
     * Any factor counts, whatever its status, unlike the trait's confirmed-only
     * rule.
     *
     * @return bool
     */
    #[\Override]
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
    #[\Override]
    public function authFactors(): Builder
    {
        $builder = $this->factors()->getQuery();

        return self::coerceFactorBuilder($builder);
    }

    /**
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Mfa\Models\Factor, $this>
     */
    public function factors(): MorphMany
    {
        return $this->morphMany(Factor::class, 'authenticatable');
    }

    /**
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
     * Stops PHPStan reading `count()` as a dynamic call to a static method.
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
     * Narrows the relation's builder to the type the contract requires.
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
