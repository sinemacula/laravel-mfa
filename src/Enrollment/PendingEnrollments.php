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
use SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException;
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
 * A model event that cancels a write this flow needs throws, so the transaction
 * it is part of rolls back rather than reporting what was not stored.
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
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function create(string $factorId, string $grantHash, ProofBinding $binding, int $generation, EnrollmentAuthorization $authority, CarbonImmutable $expiresAt): Enrollment
    {
        $enrollment = Enrollment::query()->create([
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

        return $enrollment->exists
            ? $enrollment
            : throw new WriteCanceledException('A model event cancelled the enrolment\'s save, so it did not start.');
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
        $owner      = ProofOwner::of($caller->identity);
        $enrollment = self::locked(
            Enrollment::query()
                ->where('grant_hash', $grantHash)
                ->where('authenticatable_type', $owner->type)
                ->where('authenticatable_id', $owner->key),
        )->first();
        $id     = $enrollment?->factor_id;
        $factor = $factors->first(static fn (EloquentFactor&Model $candidate): bool => LockedFactors::idOf($candidate) === $id);

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
     * The owner's enrolments through the application, as stored under the lock,
     * matched exactly: a database's collation may let another owner's through,
     * and the caller is about to delete some of them.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  string  $application
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Mfa\Models\Enrollment>
     */
    public function ofApplication(ProofOwner $owner, string $application): Collection
    {
        return $this->ofOwner($owner)
            ->filter(static fn (Enrollment $enrollment): bool => $enrollment->application === $application)
            ->values();
    }

    /**
     * Every one of the owner's enrolments, through any application, as stored
     * under the lock, matched exactly and in a stable order, for a change that
     * ends them all.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Mfa\Models\Enrollment>
     */
    public function ofOwner(ProofOwner $owner): Collection
    {
        return self::locked(Enrollment::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key))
            ->orderBy('id')
            ->get()
            ->filter(static fn (Enrollment $enrollment): bool => $enrollment->authenticatable_type === $owner->type && $enrollment->authenticatable_id === $owner->key)
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
        if (!self::belongsTo($enrollment, $binding->identityType, $binding->identityKey, $binding->application)) {
            return false;
        }

        return hash_equals($enrollment->session_id, $this->keys->session($binding->sessionId))
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
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function discard(Enrollment $enrollment, EloquentFactor&Model $factor): void
    {
        if ($factor->delete() === false) {
            throw new WriteCanceledException('A model event cancelled the pending factor\'s deletion, so its enrolment stays.');
        }

        $this->forget($enrollment);
    }

    /**
     * Delete the enrolment alone, which ends its grant.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function forget(Enrollment $enrollment): void
    {
        if ($enrollment->delete() === false) {
            throw new WriteCanceledException('A model event cancelled the enrolment\'s deletion, so its grant would have stayed usable.');
        }
    }

    /**
     * Record the challenge the enrolment's latest code went out under.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  string  $challengeId
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     */
    public function recordChallenge(Enrollment $enrollment, string $challengeId): void
    {
        if (!$enrollment->update(['challenge_id' => $challengeId])) {
            throw new WriteCanceledException('A model event cancelled the enrolment\'s save, so its code could not be confirmed.');
        }
    }

    /**
     * Count one attempt against the enrolment's own cap, and answer the count.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @return int
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     *
     * @phpstan-impure
     */
    public function countAttempt(Enrollment $enrollment): int
    {
        if ($enrollment->increment('attempts') === false) {
            throw new WriteCanceledException('A model event cancelled counting the enrolment\'s attempt.');
        }

        return $enrollment->attempts;
    }

    /**
     * Whether the enrolment is, exactly, the owner's through the application.
     *
     * @param  \SineMacula\Laravel\Mfa\Models\Enrollment  $enrollment
     * @param  string  $type
     * @param  string  $key
     * @param  string  $application
     * @return bool
     */
    private static function belongsTo(Enrollment $enrollment, string $type, string $key, string $application): bool
    {
        return $enrollment->authenticatable_type === $type
            && $enrollment->authenticatable_id   === $key
            && $enrollment->application          === $application;
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
