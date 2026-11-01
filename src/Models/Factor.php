<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Mfa\Concerns\ActsAsFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

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
 * @property string $driver
 * @property ?string $label
 * @property ?string $recipient
 * @property ?string $secret
 * @property ?string $code
 * @property ?\Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $verified_at
 * @property int $attempts
 * @property ?\Carbon\CarbonInterface $locked_until
 * @property ?\Carbon\CarbonInterface $last_attempted_at
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
        'driver',
        'label',
        'recipient',
        'secret',
        'code',
        'expires_at',
        'verified_at',
        'attempts',
        'locked_until',
        'last_attempted_at',
    ];

    /** @var list<string> The attributes that should be hidden for serialisation. */
    protected $hidden = [
        'secret',
        'code',
    ];

    /**
     * Create a new Factor bound to the package-configured table name and,
     * unless the class names a connection of its own, the storage connection
     * (see `Database\StorageConnection`). Reads both lazily on each
     * instantiation so runtime config swaps (tests, tenancy) take effect
     * immediately. They have to be applied here, before Eloquent reads them, so
     * this is construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable($this->resolveConfiguredTable());

        $this->connection ??= $this->resolveStorageConnection();

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
            'driver'               => 'string',
            'label'                => 'string',
            'recipient'            => 'string',
            'secret'               => 'encrypted',
            'code'                 => 'encrypted',
            'expires_at'           => 'datetime',
            'verified_at'          => 'datetime',
            'locked_until'         => 'datetime',
            'last_attempted_at'    => 'datetime',
            'attempts'             => 'integer',
        ];
    }

    /**
     * Read the storage connection, or `null` (the default connection) while the
     * Config facade is not yet bootstrapped.
     *
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private function resolveStorageConnection(): ?string
    {
        return Config::getFacadeRoot() === null ? null : StorageConnection::name();
    }

    /**
     * Read the configured factor table, falling back to `'mfa_factors'` when
     * the key is absent or the Config facade is not yet bootstrapped.
     *
     * @return string
     */
    private function resolveConfiguredTable(): string
    {
        try {
            $table = Config::string('mfa.factor.table', 'mfa_factors');
        } catch (\Throwable) {
            return 'mfa_factors';
        }

        return $table === '' ? 'mfa_factors' : $table;
    }
}
