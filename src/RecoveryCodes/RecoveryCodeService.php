<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\RecoveryCodes;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RecoveryCode;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Database\OpenTransaction;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventDispatcher;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesGenerated;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesRemoved;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Factors\ConfirmedFactors;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
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
 * The application of every operation is the one it is given, and no request is
 * read.
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

    /** @var \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeRows The identity's stored codes and the set's state. */
    private RecoveryCodeRows $rows;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeGenerator  $generator
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     * @param  \SineMacula\Laravel\Mfa\Events\EventDispatcher  $events
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     */
    public function __construct(

        /** The container the hasher is read from on every call. */
        private Container $container,

        /** The configuration the settings and models are read from on every call. */
        private Repository $config,

        /** The generator of new sets. */
        private RecoveryCodeGenerator $generator,

        /** The guard that refuses a machine or inactive identity. */
        private OperationGuard $guard,

        /** The attempt service a redemption is counted through. */
        private AttemptService $attempts,

        /** The dispatcher of the recovery code events. */
        private EventDispatcher $events,

        /** The reader of the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,
    ) {
        $this->rows = new RecoveryCodeRows($config);
    }

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
     * event cancels throws `WriteCanceledException` and rolls it all back.
     * `RecoveryCodesGenerated` is dispatched once it has committed. The codes
     * are returned unformatted, in the order they were drawn. The application
     * is the current request's unless the caller names the one it acts on, and
     * the event names the sign-in given, when the operation captured one.
     *
     * A gate, when given, refuses by throwing: it runs before the codes are
     * drawn, given no factors, and again first under the lock, given the
     * identity's factors as stored there, so what it checks holds when the old
     * set is replaced, and a refusal leaves the old set intact.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  (\Closure(?\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>): void)|null  $gate
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @param  ?string  $signInId
     * @return list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     * @throws \Throwable
     */
    public function generate(
        MultiFactorAuthenticatable $identity,
        string $application,
        ?Actor $actor = null,
        ?\Closure $gate = null,
        ?ClientContext $client = null,
        ?string $signInId = null,
    ): array {
        ['codes' => $codes, 'generation' => $generation] = $this->replaceSet($identity, $application, $gate);

        // Dispatched from out here, so inside a caller's transaction it keeps
        // its place among the caller's events rather than running ahead of them
        // with this nested transaction's.
        $this->reportGenerated($identity, $application, count($codes), $generation, $actor, $client, $signInId);

        return $codes;
    }

    /**
     * Everything `generate()` does up to the commit, reporting nothing: for a
     * caller that must tell a refusal from a listener's failure once the change
     * has committed, and reports with `reportGenerated()` itself. Returns the
     * codes, once, as secrets for the response, and the set's generation.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  (\Closure(?\Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>): void)|null  $gate
     * @return array{codes: list<\SineMacula\Laravel\Mfa\Secrets\RevealedSecret>, generation: int}
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     * @throws \Throwable
     */
    public function replaceSet(MultiFactorAuthenticatable $identity, string $application, ?\Closure $gate = null): array
    {
        $this->guardGeneration($identity, $application);

        self::requireConfirmedFactor($identity->isMfaEnabled(), 'Recovery codes are issued only to an identity with a confirmed factor.');

        if ($gate !== null) {
            $gate(null);
        }

        $settings = new RecoveryCodeSettings($this->config);
        $codes    = $this->generator->generate($settings->count(), $settings->length(), $settings->alphabet());
        $hasher   = $this->hasher();
        $hashes   = array_map(static fn (string $code): string => $hasher->make($code), $codes);

        $factorModel = ConfiguredModels::factor($this->config);

        $generation = FactorStateTransaction::forIdentity($identity, new $factorModel, function (Collection $factors) use ($identity, $application, $hashes, $gate): int {

            if ($gate !== null) {
                $gate($factors);
            }

            $this->guardGeneration($identity, $application);

            $confirmed = $factors->contains(static fn (EloquentFactor&Model $factor): bool => $factor->isConfirmed());

            self::requireConfirmedFactor($confirmed, 'The identity no longer has a confirmed factor.');

            return $this->rows->replace(ProofOwner::of($identity), $hashes);
        });

        return [
            'codes'      => array_map(static fn (string $code): RevealedSecret => new RevealedSecret($code), $codes),
            'generation' => $generation,
        ];
    }

    /**
     * Report a set of the given size and generation as generated, once the
     * change it belongs to has committed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  int  $count
     * @param  int  $generation
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @param  ?string  $signInId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function reportGenerated(
        MultiFactorAuthenticatable $identity,
        string $application,
        int $count,
        int $generation,
        ?Actor $actor = null,
        ?ClientContext $client = null,
        ?string $signInId = null,
    ): void {
        $this->events->dispatch(new RecoveryCodesGenerated($this->events->context($identity, $application, $client, $signInId), $count, $generation, $actor));
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
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeAdmission
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function admission(MultiFactorAuthenticatable $identity, ProofBinding $binding, ?PendingContext $pending): ChallengeAdmission
    {
        try {
            $this->guard->identity($identity);
        } catch (OperationRefusedException $exception) {
            return ChallengeAdmission::refuse($exception->reason, $exception->getMessage());
        }

        $settings = new ApplicationSettings($this->config, $binding->application);
        $owner    = ProofOwner::of($identity);
        $known    = $this->firstFactors->forBinding($identity, $binding, $pending) !== null;

        return match (true) {
            !$settings->acceptsRecoveryCodes() => ChallengeAdmission::refuse(FailureReason::TYPE_NOT_ENABLED, 'The application does not accept recovery codes.'),
            !$this->hasConfirmedFactor($owner) => ChallengeAdmission::refuse(FailureReason::NO_FACTOR, 'The identity has no confirmed factor.'),
            !$known                            => ChallengeAdmission::refuse(FailureReason::NOT_ACCEPTED, 'The session\'s first factor is not known.'),
            default                            => ChallengeAdmission::admit(),
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
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return \SineMacula\Laravel\Mfa\RecoveryCodes\Redemption
     *
     * @throws \Throwable
     */
    public function redeem(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $code, ProofBinding $binding, ?ClientContext $client = null): Redemption
    {
        $normalized = RecoveryCodeNormalizer::normalize($code);
        $checked    = null;

        $outcome = $this->attempts->attempt(
            new Attempt($identity, null, $binding->purpose, $binding->application, $client),
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
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public function reportRedeemed(MultiFactorAuthenticatable $identity, ProofBinding $binding, int $remaining, ?ClientContext $client = null): void
    {
        $context  = $this->events->context($identity, $binding->application, $client, $binding->sessionId);
        $lowCount = (new RecoveryCodeSettings($this->config))->lowCount();

        $this->events->dispatch(new RecoveryCodeUsed($context, $remaining, $binding->purpose));

        if ($lowCount <= 0 || $remaining > $lowCount) {
            return;
        }

        $this->events->dispatch(new RecoveryCodesLow($context, $remaining, $binding->purpose));
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
        return $this->rows->status(ProofOwner::of($identity));
    }

    /**
     * Where the set of the identity the request serves for listing factors
     * stands: a pending session's when its credential allows listing them,
     * otherwise the signed-in person's; `null` when it serves nobody.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @return ?\SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeStatus
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    public function statusOfCaller(CallerContext $context): ?RecoveryCodeStatus
    {
        $caller = $this->callers->resolve($context, PendingAction::LIST_FACTORS);

        return $caller === null ? null : $this->status($caller->identity);
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
     * throws `WriteCanceledException`, which rolls the removal back with it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     * @throws \Throwable
     *
     * @imperative
     */
    public function removeSet(MultiFactorAuthenticatable $identity, ?Actor $actor = null, ?ClientContext $client = null): bool
    {
        $existed = $this->deleteSet($identity);

        if ($existed) {
            $this->reportSetRemoved($identity, $actor, null, $client);
        }

        return $existed;
    }

    /**
     * Delete the identity's recovery codes and clear when they were generated,
     * under the lock of its state row, reporting nothing, and return whether it
     * had a set: for a caller with more to do before the removal is reported,
     * which then calls `reportSetRemoved()`. Refused and rolled back as
     * `removeSet()` is.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\WriteCanceledException
     * @throws \Throwable
     *
     * @imperative
     */
    public function deleteSet(MultiFactorAuthenticatable $identity): bool
    {
        OpenTransaction::assertOpen('A recovery code set is removed only inside the identity\'s factor state transaction.');

        return $this->rows->delete(ProofOwner::of($identity));
    }

    /**
     * Report that the identity's recovery code set was removed, once the
     * storage connection commits.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @param  ?string  $signInId
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function reportSetRemoved(
        MultiFactorAuthenticatable $identity,
        ?Actor $actor = null,
        ?string $application = null,
        ?ClientContext $client = null,
        ?string $signInId = null,
    ): void {
        $this->events->dispatch(new RecoveryCodesRemoved($this->events->context($identity, $application, $client, $signInId), $actor));
    }

    /**
     * Delete every code used, or replaced by a newer set, before the given
     * time, and return how many. A code still usable is never deleted, and the
     * identity's state row is left as it is. Deleted a limited batch at a time,
     * as a mass delete, so no model event fires. Dispatches nothing.
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
        return $this->rows->prune($before);
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
            throw OperationRefusedException::byPackage(FailureReason::TYPE_NOT_ENABLED, 'The application does not accept recovery codes.');
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
            throw OperationRefusedException::byPackage(FailureReason::NO_FACTOR, $detail);
        }
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
        $usable  = $this->rows->usable(ProofOwner::of($identity));
        $hashes  = $usable->map(static fn (Model&RecoveryCode $code): string => $code->getCodeHash() ?? '')->all();
        $index   = RecoveryCodeMatcher::find($this->hasher(), $hashes, $normalized);
        $matched = $index === null ? null : $usable->get($index);

        if ($matched === null || !$this->rows->markUsed($matched)) {
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
     * Determine whether the identity still has a confirmed factor, read with a
     * locking read under the identity's lock. The factors are matched to the
     * owner exactly and their status compared in PHP (see
     * `Factors\ConfirmedFactors`), as a collation that ignores case or padding
     * would let a status such as `CONFIRMED` admit a code in SQL.
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

        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor> $factors */
        $factors = $factor->newQuery()
            ->where($typeColumn, $owner->type)
            ->where($keyColumn, $owner->key)
            ->lockForUpdate()
            ->get();

        return ConfirmedFactors::isAmong($factors->filter(static fn (EloquentFactor&Model $stored): bool => FactorOwnerColumns::owns($stored, $owner->type, $owner->key)));
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
