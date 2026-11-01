<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * An identity's factor state as a whole: its verification generation, its
 * re-enrolment obligation, its consecutive failures across every factor and the
 * lockout they applied, and its recovery code set's generation and time. Its
 * row is also the lock every change to that state takes first (see
 * `Support\FactorStateTransaction`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property int $verification_generation
 * @property bool $reenrollment_required
 * @property int $consecutive_failures
 * @property ?\Carbon\CarbonInterface $locked_until
 * @property int $recovery_codes_generation
 * @property ?\Carbon\CarbonInterface $recovery_codes_generated_at
 *
 * @internal
 */
final class IdentityState extends Model
{
    use HasUlids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'authenticatable_type',
        'authenticatable_id',
        'verification_generation',
        'reenrollment_required',
        'consecutive_failures',
        'locked_until',
        'recovery_codes_generation',
        'recovery_codes_generated_at',
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
        $this->setTable(TableNames::of(TableNames::IDENTITY_STATES));

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
            'authenticatable_type'        => 'string',
            'authenticatable_id'          => 'string',
            'verification_generation'     => 'integer',
            'reenrollment_required'       => 'boolean',
            'consecutive_failures'        => 'integer',
            'locked_until'                => 'datetime',
            'recovery_codes_generation'   => 'integer',
            'recovery_codes_generated_at' => 'datetime',
        ];
    }
}
