<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Codes\CodeKeys;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Models\Enrollment;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;

/**
 * The enrolments in progress: one row per pending factor, holding what its
 * grant is bound to. Every read locks the row from the write connection, once
 * the identity's factor state lock is held, so the lock order stays the
 * identity's state, its factors, the enrolment, then the owner's challenge.
 *
 * A row is matched exactly in PHP, since a database's collation may not compare
 * as exactly: the owner, the application, a keyed digest of the sign-in, and
 * what authorised it against who is asking, as a bootstrap grant serves only a
 * pending session and any other grant only an active one. A grant is live only
 * while its stored expiry is still ahead and the identity's verification
 * generation has not moved since it started.
 *
 * Stateless: the key is read from the configuration on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingEnrollments
{
    /** @var \SineMacula\Laravel\Mfa\Codes\CodeKeys The keyed digest of a sign-in. */
    private CodeKeys $keys;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(Repository $config)
    {
        $this->keys = new CodeKeys($config);
    }

    /**
     * Record the enrolment of the pending factor under the binding.
     *
     * @param  string  $factorId
     * @param  string  $grantHash
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  int  $generation
     * @param  \SineMacula\Laravel\Mfa\Enums\EnrollmentAuthorization  $authority
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return \SineMacula\Laravel\Mfa\Models\Enrollment
     *
     * @throws \InvalidArgumentException
     */
    public function create(string $factorId, string $grantHash, ProofBinding $binding, int $generation, EnrollmentAuthorization $authority, CarbonImmutable $expiresAt): Enrollment
    {
        return Enrollment::query()->create([
            'factor_id'            => $factorId,
            'authenticatable_type' => $binding->identityType,
            'authenticatable_id'   => $binding->identityKey,
            'grant_hash'           => $grantHash,
            'application'          => $binding->application,
            'session_id'           => $this->keys->session($binding->sessionId),
            'generation'           => $generation,
            'authority'            => $authority,
            'expires_at'           => $expiresAt,
            'attempts'             => 0,
        ]);
    }

    /**
     * The enrolment the grant holds and its pending factor, as stored under the
     * lock, when it is bound to who is asking; `null` for any other grant, so
     * none of them can be told apart.
     *
     * @formatter:off
     *
     * @param  string  $grantHash
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return ?array{\SineMacula\Laravel\Mfa\Models\Enrollment, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor}
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     */
    public function granted(string $grantHash, ProofBinding $binding, Caller $caller, Collection $factors): ?array
    {
        $enrollment = self::locked(Enrollment::query()->where('grant_hash', $grantHash))->first();
        $id         = $enrollment?->factor_id;
        $factor     = $factors->first(static fn (EloquentFactor&Model $candidate): bool => LockedFactors::idOf($candidate) === $id);

        return $enrollment !== null && $factor !== null && $this->isBound($enrollment, $binding, $caller->pending !== null)
            ? [$enrollment, $factor]
            : null;
    }

    /**
     * The enrolment of the pending factor, as stored under the lock.
     *
     * @param  string  $factorId
     * @return ?\SineMacula\Laravel\Mfa\Models\Enrollment
     */
    public function forFactor(string $factorId): ?Enrollment
    {
        return self::locked(Enrollment::query()->where('factor_id', $factorId))->first();
    }

    /**
     * The owner's enrolments through the application, as stored under the lock.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $application
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Mfa\Models\Enrollment>
     */
    public function ofApplication(ProofOwner $owner, string $application): Collection
    {
        return self::locked(Enrollment::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key))
            ->get()
            ->filter(static fn (Enrollment $enrollment): bool => $enrollment->application === $application)
            ->values();
    }

    /**
     * Whether the enrolment is bound to the binding's identity, application and
     * sign-in, and its authority serves who is asking.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  bool  $pending
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function isBound(Enrollment $enrollment, ProofBinding $binding, bool $pending): bool
    {
        return $enrollment->authenticatable_type === $binding->identityType
            && $enrollment->authenticatable_id   === $binding->identityKey
            && $enrollment->application          === $binding->application
            && hash_equals($enrollment->session_id, $this->keys->session($binding->sessionId))
            && ($enrollment->authority === EnrollmentAuthorization::BOOTSTRAP) === $pending;
    }

    /**
     * Whether the enrolment's grant is live: its expiry is ahead and the
     * identity's verification generation has not moved since it started.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function isLive(Enrollment $enrollment, MultiFactorAuthenticatable $identity): bool
    {
        return $enrollment->expires_at->getTimestamp() > CarbonImmutable::now()->getTimestamp()
            && $enrollment->generation === VerificationGeneration::current($identity);
    }

    /**
     * Delete the enrolment and its pending factor. Delivered code rows stay,
     * since the caps on sending read them, so starting again cannot reset those
     * caps.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     */
    public function discard(Enrollment $enrollment, EloquentFactor&Model $factor): void
    {
        if ($factor->delete() === false) {
            throw new WriteCancelledException('A model event cancelled the pending factor\'s deletion, so its enrolment stays.');
        }

        $enrollment->delete();
    }

    /**
     * The query, locking what it reads from the write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Enrollment>  $query
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Enrollment>
     */
    private static function locked(Builder $query): Builder
    {
        return WriteConnection::query($query)->lockForUpdate();
    }
}
