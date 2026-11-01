<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\ActsAsRecoveryCode;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode as RecoveryCodeContract;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * Default shipped recovery code model.
 *
 * One code of an identity's recovery code set, stored as a salted hash, bound
 * to the identity through the `authenticatable()` relation. ULID primary key,
 * kept on the storage connection with the package's other tables. An
 * application may replace it through `mfa.recovery_codes.model` with a
 * subclass, or with its own Eloquent model implementing the `RecoveryCode`
 * contract (the `ActsAsRecoveryCode` trait does).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $code_hash
 * @property int $generation
 * @property ?\Carbon\CarbonInterface $used_at
 * @property ?\Carbon\CarbonInterface $replaced_at
 *
 * @inheritable
 */
class RecoveryCode extends Model implements RecoveryCodeContract
{
    use ActsAsRecoveryCode, HasUlids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'authenticatable_type',
        'authenticatable_id',
        'code_hash',
        'generation',
        'used_at',
        'replaced_at',
    ];

    /** @var list<string> The attributes that should be hidden for serialisation. */
    protected $hidden = [
        'code_hash',
    ];

    /**
     * Create the code on the configured table and, unless the class names a
     * connection of its own, the storage connection (see `Database\TableNames`
     * and `Database\StorageConnection`), read when it is built so a change in
     * the configuration applies to the next one.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(TableNames::of(TableNames::RECOVERY_CODES));

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
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'code_hash'            => 'string',
            'generation'           => 'integer',
            'used_at'              => 'datetime',
            'replaced_at'          => 'datetime',
        ];
    }
}
