<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Identities;

use Illuminate\Auth\Authenticatable as AuthenticatableTrait;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * An authenticatable that does not implement `MultiFactorAuthenticatable`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainUser extends Model implements Authenticatable
{
    use AuthenticatableTrait;

    /** @var string|null */
    protected $table = 'test_users';

    /** @var list<string> */
    protected $fillable = [
        'email',
        'mfa_enabled',
    ];
}
