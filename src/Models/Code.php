<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * A code sent by SMS or email for a factor: the keyed hash of the code and its
 * binding (factor, purpose, application and session), the attempts made against
 * it, how often and when it was sent (last, and each time), when it expires and
 * when it was used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $factor_id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $purpose
 * @property string $application
 * @property ?string $session_id
 * @property string $code_hash
 * @property int $attempts
 * @property int $sends
 * @property \Carbon\CarbonInterface $sent_at
 * @property list<int> $sent_times
 * @property \Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $consumed_at
 * @property \Carbon\CarbonInterface $created_at
 * @property \Carbon\CarbonInterface $updated_at
 *
 * @internal
 */
final class Code extends Model
{
    use HasUlids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'factor_id',
        'authenticatable_type',
        'authenticatable_id',
        'purpose',
        'application',
        'session_id',
        'code_hash',
        'attempts',
        'sends',
        'sent_at',
        'sent_times',
        'expires_at',
        'consumed_at',
    ];

    /** @var list<string> The attributes that should be hidden for serialisation. */
    protected $hidden = [
        'code_hash',
        'session_id',
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
        $this->setTable(TableNames::of(TableNames::CODES));

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
            'purpose'              => 'string',
            'application'          => 'string',
            'session_id'           => 'string',
            'code_hash'            => 'string',
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'attempts'             => 'integer',
            'sends'                => 'integer',
            'sent_at'              => 'datetime',
            'sent_times'           => 'array',
            'expires_at'           => 'datetime',
            'consumed_at'          => 'datetime',
        ];
    }
}
