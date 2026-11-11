<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * A code sent by SMS or email, stored as a keyed hash bound to its factor,
 * purpose, application and session.
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
 * @property string $destination_hash
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

    /** @var list<string> */
    protected $fillable = [
        'factor_id',
        'authenticatable_type',
        'authenticatable_id',
        'purpose',
        'application',
        'session_id',
        'destination_hash',
        'code_hash',
        'attempts',
        'sends',
        'sent_at',
        'sent_times',
        'expires_at',
        'consumed_at',
    ];

    /** @var list<string> */
    protected $hidden = [
        'code_hash',
        'session_id',
        'destination_hash',
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
        $this->setTable(TableNames::of(TableNames::CODES));

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
            'purpose'              => 'string',
            'application'          => 'string',
            'session_id'           => 'string',
            'destination_hash'     => 'string',
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
