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
 * An identity's one recovery code set, shared by every application: a fallback
 * for lost factors, never a factor of its own.
 *
 * A set is replaced under the identity's factor state lock, so a redemption
 * sees the old set or the new one, never both. Codes are stored with the salted
 * Laravel hasher, and events are dispatched once the change commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RecoveryCodeService
{
    /** @var string Type a recovery code is reported and proved as. */
    public const string TYPE = 'recovery_code';

    /** @var \SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeRows */
    private RecoveryCodeRows $rows;

    /**
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

        /** The hasher is resolved per call. */
        private Container $container,

        /** Read on every call so changed settings apply. */
        private Repository $config,

        /** Draws new sets. */
        private RecoveryCodeGenerator $generator,

        /** Refuses a machine or inactive identity. */
        private OperationGuard $guard,

        /** Counts redemptions as attempts. */
        private AttemptService $attempts,

        /** Dispatches the recovery code events. */
        private EventDispatcher $events,

        /** Reads the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** Resolves who the request serves. */
        private CallerContextResolver $callers,
    ) {
        $this->rows = new RecoveryCodeRows($config);
    }

    /**
     * Replace any earlier set and return the new codes, revealed once.
     *
     * The gate refuses by throwing; it runs before drawing with no factors and
     * again under the lock with the stored factors, so a refusal keeps the old
     * set.
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

        // Outside the transaction so it keeps its order in a caller's events.
        $this->reportGenerated($identity, $application, count($codes), $generation, $actor, $client, $signInId);

        return $codes;
    }

    /**
     * `generate()` without the event, for a caller that must tell a refusal
     * from a listener's failure and reports with `reportGenerated()` itself.
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
     * Whether a code may be tried, read under the caller's lock; a refusal is
     * neither hashed nor counted.
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
     * One counted attempt against every unused code, inside the caller's factor
     * state transaction; it reports nothing, so a later refusal rolls the use
     * back.
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
     * Null when the request serves nobody allowed to list factors.
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
     * Delete the set inside the factor state transaction and return whether
     * there was one; the generation is kept so it only ever rises.
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
     * `removeSet()` without the event, for a caller that reports with
     * `reportSetRemoved()` itself.
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
     * Delete codes used or replaced before the time, without model events.
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
     * An attempt no lockout refused always runs the check.
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
     * Status is compared in PHP because a case- or padding-insensitive
     * collation would let `CONFIRMED` admit a code in SQL.
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
     * @return \Illuminate\Contracts\Hashing\Hasher
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function hasher(): Hasher
    {
        return $this->container->make(Hasher::class);
    }
}
