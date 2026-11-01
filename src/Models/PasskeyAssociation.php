<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * The association of one of an identity's passkeys with a factor: a passkey is
 * a factor only through such a record. The credential itself, and its
 * ceremonies, belong to the authentication layer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $factor_id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $credential_id_hash
 * @property string $credential_id
 *
 * @internal
 */
final class PasskeyAssociation extends Model
{
    use HasUlids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'factor_id',
        'authenticatable_type',
        'authenticatable_id',
        'credential_id_hash',
        'credential_id',
    ];

    /**
     * Create the record on the table and connection the package configures (see
     * `Database\TableNames` and `Database\StorageConnection`), read when it is
     * built so a change in the configuration applies to the next one.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(TableNames::of(TableNames::PASSKEY_ASSOCIATIONS));

        $this->connection ??= StorageConnection::forModel();

        parent::__construct($attributes);
    }

    /**
     * Columns that receive a generated unique identifier on insert.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return ['id'];
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
            'factor_id'            => 'string',
            'credential_id_hash'   => 'string',
            'credential_id'        => 'string',
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
        ];
    }
}
