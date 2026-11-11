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
 * The shipped recovery code model, stored as a salted hash and replaceable
 * through `mfa.recovery_codes.model`.
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

    /** @var list<string> */
    protected $fillable = [
        'authenticatable_type',
        'authenticatable_id',
        'code_hash',
        'generation',
        'used_at',
        'replaced_at',
    ];

    /** @var list<string> */
    protected $hidden = [
        'code_hash',
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
        $this->setTable(TableNames::of(TableNames::RECOVERY_CODES));

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
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'code_hash'            => 'string',
            'generation'           => 'integer',
            'used_at'              => 'datetime',
            'replaced_at'          => 'datetime',
        ];
    }
}
