<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An identity model that uses `HasFactors` without overriding anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
final class FactorHolder extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait, HasFactors;

    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
    ];
}
