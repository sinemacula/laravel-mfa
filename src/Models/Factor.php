<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * Default shipped Factor Eloquent model.
 *
 * Polymorphic factor record bound to an authenticatable identity via the
 * `authenticatable()` morphTo relation. ULID primary key. Kept on the storage
 * connection with the package's other tables. Swappable via
 * `config('mfa.factor.model')` / `mfa.factor.table` as the package's default
 * Eloquent adapter. Subclasses MUST continue satisfying the `Factor`
 * persistence boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $type
 * @property ?string $label
 * @property ?string $destination
 * @property ?string $credential_reference
 * @property ?string $secret
 * @property ?string $totp_algorithm
 * @property ?int $totp_digits
 * @property ?int $totp_period
 * @property ?int $last_accepted_step
 * @property string $status
 * @property bool $preferred
 * @property int $consecutive_failures
 * @property ?\Carbon\CarbonInterface $disabled_at
 * @property ?string $application
 * @property ?\Carbon\CarbonInterface $confirmed_at
 * @property ?\Carbon\CarbonInterface $last_used_at
 * @property ?string $code
 * @property ?\Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $verified_at
 *
 * @inheritable
 */
class Factor extends Model implements EloquentFactor
{
    use ActsAsFactor, HasUlids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'authenticatable_type',
        'authenticatable_id',
        'type',
        'label',
        'destination',
        'credential_reference',
        'secret',
        'totp_algorithm',
        'totp_digits',
        'totp_period',
        'last_accepted_step',
        'status',
        'preferred',
        'consecutive_failures',
        'disabled_at',
        'application',
        'confirmed_at',
        'last_used_at',
        'code',
        'expires_at',
        'verified_at',
    ];

    /** @var list<string> The attributes that should be hidden for serialisation. */
    protected $hidden = [
        'secret',
        'code',
        'destination',
        'credential_reference',
    ];

    /** @var array<string, mixed> The attributes' values before anything is set: a new factor is pending, not preferred and has not failed. */
    protected $attributes = [
        'status'               => 'pending',
        'preferred'            => false,
        'consecutive_failures' => 0,
    ];

    /**
     * Create a new Factor bound to the package-configured table name and,
     * unless the class names a connection of its own, the storage connection
     * (see `Database\StorageConnection`). Reads both lazily on each
     * instantiation so runtime config swaps (tests, tenancy) take effect
     * immediately. They have to be applied here, before Eloquent reads them, so
     * this is construction rather than model behaviour.
     *
     * The connection is always named, the default one included: Eloquent gives
     * a related model that names none its parent's connection, so an identity
     * on another connection would otherwise read and write its factors there.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(TableNames::of(TableNames::FACTORS));

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
            'type'                 => 'string',
            'label'                => 'string',
            'destination'          => 'string',
            'credential_reference' => 'string',
            'secret'               => 'encrypted',
            'totp_algorithm'       => 'string',
            'totp_digits'          => 'integer',
            'totp_period'          => 'integer',
            'last_accepted_step'   => 'integer',
            'status'               => 'string',
            'preferred'            => 'boolean',
            'consecutive_failures' => 'integer',
            'disabled_at'          => 'datetime',
            'application'          => 'string',
            'confirmed_at'         => 'datetime',
            'last_used_at'         => 'datetime',
            'code'                 => 'encrypted',
            'expires_at'           => 'datetime',
            'verified_at'          => 'datetime',
        ];
    }
}
