<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * An identity model keyed by a UUID, using `HasFactors` without overriding
 * anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
final class UuidIdentity extends Model implements Authenticatable, MultiFactorAuthenticatable
{
    use AuthenticatableTrait, HasFactors, HasUuids;

    /** @var string|null */
    protected $table = 'test_string_keyed_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
    ];
}
