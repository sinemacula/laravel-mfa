<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\JoinClause;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Generates, redeems, reports, removes and prunes an identity's recovery codes:
 * a fallback for lost factors, never a factor of their own. A redemption is
 * reached through `Verification\VerificationService`, which holds the
 * identity's lock, makes and hands over the proof, and reports the
 * verification; generating a set for the person the request serves is gated by
 * `RecoveryCodeIssuance`.
 *
 * An identity has one set, shared by every application; each application
 * decides whether it accepts recovery codes. A set is generated for an identity
 * with a confirmed factor only, and replaces any earlier one in the identity's
 * factor state transaction (see `Support\FactorStateTransaction`), so a
 * redemption, which takes the same lock, finds either the old set intact or the
 * new one, never both and never neither. Codes are stored hashed with the
 * application's Laravel hasher, salted, and a redemption checks the submitted
 * code against every unused code of the set as one attempt, with the same work
 * whichever code matches, if any. Every event is dispatched through
 * `Events\EventDispatcher`, once the change it reports has committed.
 *
 * The application of every operation is the current request's (see
 * `Proofs\ProofService::application()`), read once per call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeService
{
    /** @var string The type a recovery code is reported and proved as. */
    public const string TYPE = 'recovery_code';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGenerator  $generator
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofService  $proofs
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     */
    public function __construct(

        /** The container the hasher and the request are read from on every call. */
        private Container $container,

        /** The configuration the settings and models are read from on every call. */
        private Repository $config,

        /** The generator of new sets. */
        private RecoveryCodeGenerator $generator,

        /** The guard that refuses a machine or inactive identity. */
        private OperationGuard $guard,

        /** The attempt service a redemption is counted through. */
        private AttemptService $attempts,

        /** The application of the request. */
        private ProofService $proofs,

        /** The dispatcher of the recovery code events. */
        private EventDispatcher $events,

        /** The reader of the session's first factor. */
        private SessionFirstFactor $firstFactors,
    ) {}

    /**
     * Generate a new set for the identity, replacing any earlier one, and
     * return its codes, once, as secrets for the response.
     *
     * Refused with an `OperationRefusedException` for a machine or inactive
     * identity, when the application does not accept recovery codes
     * (`type_not_enabled`), and when the identity has no confirmed factor
     * (`no_factor`), checked again under the lock. The codes are drawn and
     * hashed before the lock is taken; under it, every code of the identity not
     * yet replaced is marked replaced, the new codes are stored under the next
     * generation, and the generation and its time are recorded on the
     * identity's state row, so all of it commits or none does: a save a model
     * event cancels throws `WriteCancelledException` and rolls it all back.
     * `RecoveryCodesGenerated` is dispatched once it has committed. The codes
     * are returned unformatted, in the order they were drawn. The application
     * is the current request's unless the caller names the one it acts on.
     *
     * A gate, when given, refuses by throwing: it runs before the codes are
     * drawn, and again first under the lock, so what it checks holds when the
     * old set is replaced, and a refusal leaves the old set intact.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?string  $application
     * @param  (\Closure(): void)|null  $gate
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     * @throws \Throwable
     */
    public function generate(MultiFactorAuthenticatable $identity, ?Actor $actor = null, ?string $application = null, ?\Closure $gate = null): array
    {
        $application ??= $this->proofs->application();

        $this->guardGeneration($identity, $application);

        self::requireConfirmedFactor($identity->isMfaEnabled(), 'Recovery codes are issued only to an identity with a confirmed factor.');

        if ($gate !== null) {
            $gate();
        }

        $settings = new RecoveryCodeSettings($this->config);
        $codes    = $this->generator->generate($settings->count(), $settings->length(), $settings->alphabet());
        $hasher   = $this->hasher();
        $hashes   = array_map(static fn (string $code): string => $hasher->make($code), $codes);

        $factorModel = ConfiguredModels::factor($this->config);

        FactorStateTransaction::forIdentity($identity, new $factorModel, function (Collection $factors) use ($identity, $application, $hashes, $actor, $gate): void {

            if ($gate !== null) {
                $gate();
            }

            $this->guardGeneration($identity, $application);

            $confirmed = $factors->contains(static fn (EloquentFactor&Model $factor): bool => $factor->isConfirmed());

            self::requireConfirmedFactor($confirmed, 'The identity no longer has a confirmed factor.');

            $generation = $this->replace(ProofOwner::of($identity), $hashes);

            $this->events->dispatch(new RecoveryCodesGenerated($this->events->context($identity, $application), count($hashes), $generation, $actor));
        });

        return array_map(static fn (string $code): RevealedSecret => new RevealedSecret($code), $codes);
    }

    /**
     * Whether a recovery code may be tried for the identity under the binding,
     * read under its factor state lock, which the caller holds: it must be an
     * active person, on an application that accepts recovery codes, with a
     * confirmed factor as stored, and a session whose first factor is known.
     * Nothing is hashed for a refused attempt, and nothing is counted.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function admission(MultiFactorAuthenticatable $identity, ProofBinding $binding): ChallengeAdmission
    {
        try {
            $this->guard->identity($identity);
        } catch (OperationRefusedException $exception) {
            return ChallengeAdmission::refuse($exception->reason, $exception->getMessage());
        }

        $settings = new ApplicationSettings($this->config, $binding->application);
        $owner    = ProofOwner::of($identity);

        return match (true) {
            !$settings->acceptsRecoveryCodes()               => ChallengeAdmission::refuse(FailureReason::TYPE_NOT_ENABLED, 'The application does not accept recovery codes.'),
            !$this->hasConfirmedFactor($owner)               => ChallengeAdmission::refuse(FailureReason::NO_FACTOR, 'The identity has no confirmed factor.'),
            !$this->hasKnownFirstFactor($identity, $binding) => ChallengeAdmission::refuse(FailureReason::NOT_ACCEPTED, 'The session\'s first factor is not known.'),
            default                                          => ChallengeAdmission::admit(),
        };
    }

    /**
     * Redeem a code under the binding: one attempt against every unused code of
     * the identity's set, inside the identity's factor state transaction, which
     * the caller holds. It records no proof and reports nothing, so a refusal
     * that follows rolls the code's use back with the count.
     *
     * The attempt is made through the attempt service: refused without checking
     * anything while a lockout applies, and counted against the identity
     * otherwise. The submitted code, normalised (see `RecoveryCodeNormalizer`),
     * is checked against every unused code of the current generation with the
     * hasher, without stopping at a match, and a match is marked used by a
     * statement that changes it only while it is still unused. A malformed code
     * is checked the same way, against a placeholder, and matches nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\Redemption
     *
     * @throws \Throwable
     */
    public function redeem(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $code, ProofBinding $binding): Redemption
    {
        $normalized = RecoveryCodeNormalizer::normalize($code);
        $checked    = null;

        $outcome = $this->attempts->attempt(
            new Attempt($identity, null, $binding->purpose, $binding->application),
            function () use ($identity, $normalized, &$checked): bool {

                $checked = $this->check($identity, $normalized);

                return $checked->passed;
            },
        );

        if ($outcome->lockout !== null) {
            return Redemption::refused(FailureReason::LOCKED, $outcome->lockout->detail(), $outcome->lockout->until);
        }

        return self::checked($checked);
    }

    /**
     * Report a redemption that left the given number of codes unused, once it
     * has committed: `RecoveryCodeUsed`, and `RecoveryCodesLow` when the set is
     * left at or below its low count.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  int  $remaining
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function reportRedeemed(MultiFactorAuthenticatable $identity, ProofBinding $binding, int $remaining): void
    {
        $context  = $this->events->context($identity, $binding->application);
        $lowCount = (new RecoveryCodeSettings($this->config))->lowCount();

        $this->events->dispatch(new RecoveryCodeUsed($context, $remaining, $binding->purpose));

        if ($lowCount > 0 && $remaining <= $lowCount) {
            $this->events->dispatch(new RecoveryCodesLow($context, $remaining, $binding->purpose));
        }
    }

    /**
     * Where the identity's set stands, read in one statement from the write
     * connection, so the count and the generation it counts are of the same
     * set. No lock is taken.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function status(MultiFactorAuthenticatable $identity): RecoveryCodeStatus
    {
        $owner = ProofOwner::of($identity);
        $code  = $this->codeModel();
        $state = new IdentityState;

        [$typeColumn, $keyColumn] = self::ownerColumns($code);

        $codes      = $code->getTable();
        $generation = $state->qualifyColumn('recovery_codes_generation');
        $generated  = $state->qualifyColumn('recovery_codes_generated_at');

        $query = WriteConnection::query($state->newQuery())
            ->leftJoin($codes, static function (JoinClause $join) use ($state, $code, $codes, $typeColumn, $keyColumn, $generation): void {
                $join->on($codes . '.' . $typeColumn, '=', $state->qualifyColumn('authenticatable_type'))
                    ->on($codes . '.' . $keyColumn, '=', $state->qualifyColumn('authenticatable_id'))
                    ->on($codes . '.' . $code->getGenerationName(), '=', $generation)
                    ->whereNull($codes . '.' . $code->getUsedAtName())
                    ->whereNull($codes . '.' . $code->getReplacedAtName());
            })
            ->where($state->qualifyColumn('authenticatable_type'), $owner->type)
            ->where($state->qualifyColumn('authenticatable_id'), $owner->key)
            ->groupBy($generation, $generated)
            ->select([$generation, $generated]);

        $row = $query->selectRaw('count(' . $query->getQuery()->getGrammar()->wrap($codes . '.' . $code->getKeyName()) . ') as remaining')->first();

        $remaining = $row?->getAttribute('remaining');
        $at        = $row?->recovery_codes_generated_at;

        return new RecoveryCodeStatus(
            is_numeric($remaining) ? (int) $remaining : 0,
            $row->recovery_codes_generation ?? 0,
            $at === null ? null : CarbonImmutable::instance($at),
        );
    }

    /**
     * Remove the identity's set, as with its last confirmed factor: every code
     * row is deleted and the set's time cleared; the generation is kept, so it
     * only ever rises. `RecoveryCodesRemoved` is dispatched once the removal
     * commits when there was a set, used up or not, or any code row. Returns
     * whether there was.
     *
     * It must run inside the identity's factor state transaction, holding its
     * lock, as part of the change that removes the factor; a call with no
     * transaction open on the storage connection is refused with a
     * `LogicException`, and a save of the state row a model event cancels
     * throws `WriteCancelledException`, which rolls the removal back with it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     * @throws \Throwable
     *
     * @imperative
     */
    public function removeSet(MultiFactorAuthenticatable $identity, ?Actor $actor = null): bool
    {
        self::requireTransaction();

        $owner   = ProofOwner::of($identity);
        $state   = $this->lockedState($owner);
        $deleted = $this->owned($this->codeModel(), $owner)->toBase()->delete();
        $existed = $state->recovery_codes_generated_at !== null || $deleted > 0;

        if ($state->recovery_codes_generated_at !== null) {
            $state->recovery_codes_generated_at = null;
            self::save($state);
        }

        if ($existed) {
            $this->events->dispatch(new RecoveryCodesRemoved($this->events->context($identity, $this->proofs->application()), $actor));
        }

        return $existed;
    }

    /**
     * Delete every code used, or replaced by a newer set, before the given
     * time, and return how many. A code still usable is never deleted, and the
     * identity's state row is left as it is. Dispatches nothing.
     *
     * @param  \Carbon\CarbonInterface  $before
     * @return int
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     *
     * @imperative
     */
    public function prune(CarbonInterface $before): int
    {
        $code = $this->codeModel();

        return $code->newQuery()
            ->toBase()
            ->where(static function (QueryBuilder $query) use ($code, $before): void {
                $query->where($code->getUsedAtName(), '<', $before)
                    ->orWhere($code->getReplacedAtName(), '<', $before);
            })
            ->delete();
    }

    /**
     * Refuse generating a set for a machine or inactive identity, or on an
     * application that does not accept recovery codes.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function guardGeneration(MultiFactorAuthenticatable $identity, string $application): void
    {
        $this->guard->identity($identity);

        if (!(new ApplicationSettings($this->config, $application))->acceptsRecoveryCodes()) {
            throw new OperationRefusedException(FailureReason::TYPE_NOT_ENABLED, 'The application does not accept recovery codes.');
        }
    }

    /**
     * Refuse generating a set for an identity without a confirmed factor.
     *
     * @param  bool  $confirmed
     * @param  string  $detail
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function requireConfirmedFactor(bool $confirmed, string $detail): void
    {
        if (!$confirmed) {
            throw new OperationRefusedException(FailureReason::NO_FACTOR, $detail);
        }
    }

    /**
     * Refuse removing a set outside a transaction on the storage connection:
     * the removal is part of the change that removes the last confirmed factor.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private static function requireTransaction(): void
    {
        OpenTransaction::assertOpen('A recovery code set is removed only inside the identity\'s factor state transaction.');
    }

    /**
     * Under the identity's lock: mark every code of the identity not yet
     * replaced as replaced, store the new codes' hashes under the next
     * generation, and record the generation and its time on the identity's
     * state row. Returns the new generation. Every save must be made, so a
     * cancelled one throws and the whole replacement rolls back.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  list<string>  $hashes
     * @return int
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     */
    private function replace(ProofOwner $owner, array $hashes): int
    {
        $now   = CarbonImmutable::now();
        $state = $this->lockedState($owner);
        $model = $this->codeModel();

        $generation = $state->recovery_codes_generation + 1;

        $this->owned($model, $owner)
            ->whereNull($model->getReplacedAtName())
            ->update([$model->getReplacedAtName() => $now]);

        [$typeColumn, $keyColumn] = self::ownerColumns($model);

        foreach ($hashes as $hash) {
            $code = $model->newInstance();

            $code->setAttribute($typeColumn, $owner->type);
            $code->setAttribute($keyColumn, $owner->key);
            $code->setAttribute($model->getGenerationName(), $generation);
            $code->setAttribute($model->getCodeHashName(), $hash);
            self::save($code);
        }

        $state->recovery_codes_generation   = $generation;
        $state->recovery_codes_generated_at = $now;
        self::save($state);

        return $generation;
    }

    /**
     * Under the identity's lock: check the normalised code against every unused
     * code of the current generation and mark the match used.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?string  $normalized
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\Redemption
     *
     * @throws \Throwable
     */
    private function check(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] ?string $normalized): Redemption
    {
        $usable  = $this->usableCodes(ProofOwner::of($identity));
        $hashes  = $usable->map(static fn (Model&RecoveryCode $code): string => $code->getCodeHash() ?? '')->all();
        $index   = RecoveryCodeMatcher::find($this->hasher(), $hashes, $normalized);
        $matched = $index === null ? null : $usable->get($index);

        if ($matched === null || !$this->markUsed($matched)) {
            return Redemption::failed(FailureReason::INVALID_CODE, 'The code matched no unused recovery code.', $usable->count());
        }

        return Redemption::passed($usable->count() - 1);
    }

    /**
     * The redemption the attempt's check made: an attempt no lockout refused
     * always runs the check, so a missing one is a defect.
     *
     * @param  ?\SineMacula\Laravel\Mfa\RecoveryCodes\Redemption  $checked
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\Redemption
     *
     * @throws \LogicException
     */
    private static function checked(?Redemption $checked): Redemption
    {
        return $checked ?? throw new \LogicException('An attempt that was not refused checks the code.');
    }

    /**
     * Save the model, and throw when a model event cancels the save, so the
     * change it is part of rolls back rather than commit without it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCancelledException
     */
    private static function save(Model $model): void
    {
        if (!$model->save()) {
            throw new WriteCancelledException(sprintf('A model event cancelled the save of a [%s], so the change it is part of was rolled back.', $model::class));
        }
    }

    /**
     * Mark the code used, only while it is still neither used nor replaced.
     * Returns whether this redemption marked it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode  $code
     * @return bool
     *
     * @imperative
     */
    private function markUsed(Model&RecoveryCode $code): bool
    {
        return WriteConnection::query($code->newQuery())
            ->whereKey($code->getKey())
            ->whereNull($code->getUsedAtName())
            ->whereNull($code->getReplacedAtName())
            ->update([$code->getUsedAtName() => CarbonImmutable::now()]) === 1;
    }

    /**
     * The identity's codes of its current generation that are neither used nor
     * replaced, read with a locking read so a code used in the meantime is seen
     * as used.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode>
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function usableCodes(ProofOwner $owner): Collection
    {
        $model      = $this->codeModel();
        $generation = $this->lockedState($owner)->recovery_codes_generation;

        return $this->owned($model, $owner)
            ->where($model->getGenerationName(), $generation)
            ->whereNull($model->getUsedAtName())
            ->whereNull($model->getReplacedAtName())
            ->lockForUpdate()
            ->get();
    }

    /**
     * Whether the first factor of the session the binding names is known.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function hasKnownFirstFactor(MultiFactorAuthenticatable $identity, ProofBinding $binding): bool
    {
        return $this->firstFactors->forBinding($identity, $binding) !== null;
    }

    /**
     * Determine whether the identity still has a confirmed factor, read with a
     * locking read under the identity's lock.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function hasConfirmedFactor(ProofOwner $owner): bool
    {
        $model  = ConfiguredModels::factor($this->config);
        $factor = new $model;

        [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factor);

        return $factor->newQuery()
            ->where($typeColumn, $owner->type)
            ->where($keyColumn, $owner->key)
            ->where($factor->getStatusName(), FactorStatus::CONFIRMED->value)
            ->lockForUpdate()
            ->value($factor->getKeyName()) !== null;
    }

    /**
     * The identity's state row, read with a locking read: the identity's factor
     * state lock, which every caller holds, creates it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \SineMacula\Laravel\Mfa\Models\IdentityState
     *
     * @throws \Illuminate\Database\Eloquent\ModelNotFoundException
     */
    private function lockedState(ProofOwner $owner): IdentityState
    {
        return IdentityState::query()
            ->where('authenticatable_type', $owner->type)
            ->where('authenticatable_id', $owner->key)
            ->lockForUpdate()
            ->firstOrFail();
    }

    /**
     * The identity's codes, found by the owner columns of the model's
     * `authenticatable` relation, on the write connection.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode  $model
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode>
     *
     * @formatter:on
     */
    private function owned(Model&RecoveryCode $model, ProofOwner $owner): Builder
    {
        [$typeColumn, $keyColumn] = self::ownerColumns($model);

        return WriteConnection::query($model->newQuery())
            ->where($typeColumn, $owner->type)
            ->where($keyColumn, $owner->key);
    }

    /**
     * The owner columns of the recovery code model's `authenticatable`
     * relation, which an application's own model may name differently.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode  $model
     * @return array{0: string, 1: string}
     */
    private static function ownerColumns(Model&RecoveryCode $model): array
    {
        $relation = $model->authenticatable();

        return [$relation->getMorphType(), $relation->getForeignKeyName()];
    }

    /**
     * A blank instance of the configured recovery code model.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\RecoveryCode
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function codeModel(): Model&RecoveryCode
    {
        $model = ConfiguredModels::recoveryCode($this->config);

        return new $model;
    }

    /**
     * The application's hasher, resolved on every call.
     *
     * @return \Illuminate\Contracts\Hashing\Hasher
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function hasher(): Hasher
    {
        return $this->container->make(Hasher::class);
    }
}
