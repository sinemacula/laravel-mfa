<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Exceptions\UnexpectedBuilderTypeException;

/**
 * An identity whose `getAuthIdentifier()` returns an object, which must be
 * refused wherever it would name a record or a lock.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
final class NonScalarIdentifierUser extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait, HasFactors;

    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
        'mfa_enabled',
    ];

    /**
     * @return mixed
     */
    #[\Override]
    public function getAuthIdentifier(): mixed
    {
        return (object) ['id' => 1];
    }

    /**
     * @return bool
     */
    #[\Override]
    public function isMfaEnabled(): bool
    {
        return false;
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
