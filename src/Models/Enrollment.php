<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;

/**
 * An enrolment in progress: the pending factor it confirms, the hash of the
 * grant that may confirm it, the application, sign-in and verification
 * generation that grant is bound to, what authorised it, the challenge its last
 * code went out under, when it expires and the confirmation attempts made
 * against it. It never holds the grant or the sign-in's id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $factor_id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $grant_hash
 * @property string $application
 * @property string $session_id
 * @property int $generation
 * @property \SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization $authority
 * @property ?string $challenge_id
 * @property \Carbon\CarbonInterface $expires_at
 * @property int $attempts
 *
 * @internal
 */
final class Enrollment extends Model
{
    use HasUlids;

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = [
        'factor_id',
        'authenticatable_type',
        'authenticatable_id',
        'grant_hash',
        'application',
        'session_id',
        'generation',
        'authority',
        'challenge_id',
        'expires_at',
        'attempts',
    ];

    /** @var list<string> The attributes that should be hidden for serialisation. */
    protected $hidden = [
        'grant_hash',
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
        $this->setTable(TableNames::of(TableNames::ENROLLMENTS));

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
            'grant_hash'           => 'string',
            'application'          => 'string',
            'session_id'           => 'string',
            'generation'           => 'integer',
            'authority'            => EnrollmentAuthorization::class,
            'challenge_id'         => 'string',
            'authenticatable_type' => 'string',
            'authenticatable_id'   => 'string',
            'expires_at'           => 'datetime',
            'attempts'             => 'integer',
        ];
    }
}
