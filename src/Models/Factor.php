<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Concerns\ResolvesFactorRouteBinding;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;

/**
 * The shipped factor model, replaceable through `mfa.factor.model`. Route
 * binding finds only the caller's own factors.
 *
 * The suppression is for the trait initialiser `initializeActsAsFactor()`,
 * which the model-behaviour rule does not know as a framework hook.
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
 * @property ?\Carbon\CarbonInterface $locked_until
 * @property ?string $application
 * @property ?\Carbon\CarbonInterface $confirmed_at
 * @property ?\Carbon\CarbonInterface $last_used_at
 *
 * @inheritable
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour
 */
class Factor extends Model implements EloquentFactor
{
    use ActsAsFactor, HasUlids, ResolvesFactorRouteBinding;

    /** @var list<string> */
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
        'locked_until',
        'application',
        'confirmed_at',
        'last_used_at',
    ];

    /** @var list<string> */
    protected $hidden = [
        'secret',
        'destination',
        'credential_reference',
    ];

    /** @var array<string, mixed> */
    protected $attributes = [
        'status'               => 'pending',
        'preferred'            => false,
        'consecutive_failures' => 0,
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
        $this->setTable(TableNames::of(TableNames::FACTORS));

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
            'locked_until'         => 'datetime',
            'application'          => 'string',
            'confirmed_at'         => 'datetime',
            'last_used_at'         => 'datetime',
        ];
    }
}
