<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * Makes one of an identity's passkeys a factor. The credential itself belongs
 * to the authentication layer.
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

    /** @var list<string> */
    protected $fillable = [
        'factor_id',
        'authenticatable_type',
        'authenticatable_id',
        'credential_id_hash',
        'credential_id',
    ];

    /**
     * Reads the table and connection per instance so config changes apply.
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
     * @return array<int, string>
     */
    #[\Override]
    public function uniqueIds(): array
    {
        return ['id'];
    }

    /**
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
