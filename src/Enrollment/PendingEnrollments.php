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
 * Enrolment rows, one per pending factor. Reads lock from the write connection
 * after the identity's factor lock, and rows are matched again in PHP because a
 * database collation may compare loosely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingEnrollments
{
    /** @var \SineMacula\Laravel\Mfa\Codes\CodeKeys */
    private CodeKeys $keys;

    /**
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(Repository $config)
    {
        $this->keys = new CodeKeys($config);
    }

    /**
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
     * `null` for any grant not bound to the caller, so none can be told apart.
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
     * @param  string  $factorId
     * @return ?\SineMacula\Laravel\Mfa\Models\Enrollment
     */
    public function forFactor(string $factorId): ?Enrollment
    {
        return self::locked(Enrollment::query()->where('factor_id', $factorId))->first();
    }

    /**
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
     * A bootstrap grant serves only a pending session; any other only an active
     * one.
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
     * Live until expiry, and only while the verification generation is
     * unchanged.
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
     * Code rows stay so starting again cannot reset the send caps.
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
     * Returns the new count.
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
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Enrollment>  $query
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Mfa\Models\Enrollment>
     */
    private static function locked(Builder $query): Builder
    {
        return WriteConnection::query($query)->lockForUpdate();
    }
}
