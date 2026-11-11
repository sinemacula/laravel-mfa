<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;

/**
 * An enrolment in progress and the grant that may confirm it. It never holds
 * the grant or the sign-in's id, only their hashes.
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

    /** @var list<string> */
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

    /** @var list<string> */
    protected $hidden = [
        'grant_hash',
        'session_id',
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
        $this->setTable(TableNames::of(TableNames::ENROLLMENTS));

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
