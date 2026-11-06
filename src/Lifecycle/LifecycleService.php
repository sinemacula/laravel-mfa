<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Lifecycle;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\ConfiguredModels;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Support\FactorStateTransaction;

/**
 * Removes the signed-in person's factors, and lifts an identity's lockouts for
 * someone acting on it.
 *
 * A removal serves active sessions only. It is decided twice by the same checks
 * (see `RemovalGuard`): on the factors as they stand, taking no lock, so what
 * is refused anyway waits for nothing; then in the identity's factor state
 * transaction on the factors as stored under its lock, with the caller resolved
 * again and compared, so two removals cannot each see the other factor and a
 * sign-in that changed meanwhile is not acted on. Only those checks become a
 * refusal, carried out of the transaction so it rolls back: whatever the change
 * itself throws propagates, a revoker's or a transition's included, as does
 * anything a listener throws once it has committed.
 *
 * Unlocking resolves the factor under the identity's lock, and lifts temporary
 * lockouts only: failures in a row stay, and a factor disabled at the failure
 * ceiling stays disabled until another factor is proved, it is rebound or the
 * identity is reset.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LifecycleService
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Lifecycle\RemovalGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval  $removal
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     */
    public function __construct(

        /** The configuration the factor model is read from. */
        private Repository $config,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The checks every removal makes. */
        private RemovalGuard $guard,

        /** The removal every entry point shares. */
        private FactorRemoval $removal,

        /** The lockouts. */
        private AttemptService $attempts,
    ) {}

    /**
     * Remove the signed-in person's factor enrolled through the current
     * application, or say why not.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $context
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult
     *
     * @throws \Throwable
     */
    public function removeFactor(CallerContext $context, mixed $factorId): FactorRemovalResult
    {
        $caller = $this->callers->resolve($context, null);

        return $caller === null ? FactorRemovalResult::refused(FailureReason::NOT_FOUND) : $this->removeFor($caller, $factorId);
    }

    /**
     * Lift the factor's temporary lockout, as an action the actor took. `false`
     * for an id that finds none of the identity's factors, reporting nothing,
     * and when no live lockout was lifted.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  mixed  $factorId
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function unlockFactor(MultiFactorAuthenticatable $identity, mixed $factorId, Actor $actor, ?ClientContext $client = null): bool
    {
        return FactorStateTransaction::forIdentity($identity, $this->factorModel(), function (Collection $factors) use ($identity, $factorId, $actor, $client): bool {

            $factor = LockedFactors::withId($factorId, $factors);

            return $factor !== null && $this->attempts->liftLockout($identity, $factor, $actor, null, $client);
        });
    }

    /**
     * Lift the identity's temporary lockout, as an action the actor took.
     * `false` when no live lockout was lifted, though its count within the
     * window may still have been cleared.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function unlockIdentity(MultiFactorAuthenticatable $identity, Actor $actor, ?ClientContext $client = null): bool
    {
        return $this->attempts->liftLockout($identity, null, $actor, null, $client);
    }

    /**
     * Check the caller's removal on the factors as they stand, and make it
     * under the lock when nothing refuses it. Without a sign-in there is
     * nothing a step-up could have been made on, or to compare under the lock,
     * whatever a bound gate answered.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  mixed  $factorId
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult
     *
     * @throws \Throwable
     */
    private function removeFor(Caller $caller, mixed $factorId): FactorRemovalResult
    {
        $identity    = $caller->identity;
        $application = $this->callers->application($caller);
        $binding     = $this->callers->binding($caller, Purpose::STEP_UP);
        $model       = $this->factorModel();
        $refusal     = $this->refusalBeforeTheLock($identity, $application, $factorId, FactorStateTransaction::snapshot($identity, $model));

        if ($refusal !== null || $binding === null) {
            return FactorRemovalResult::refused($refusal ?? FailureReason::NOT_FRESH);
        }

        try {
            return FactorStateTransaction::forIdentity(
                $identity,
                $model,
                fn (Collection $factors): FactorRemovalResult => $this->removeUnderLock($caller, $binding, $application, $factorId, $factors),
            );
        } catch (RefusedUnderLockException $exception) {
            return FactorRemovalResult::refused($exception->refusal->reason);
        }
    }

    /**
     * Why the removal is refused on the factors given, taking no lock, or
     * `null` when nothing refuses it.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  mixed  $factorId
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     *
     * @formatter:on
     */
    private function refusalBeforeTheLock(MultiFactorAuthenticatable $identity, string $application, mixed $factorId, Collection $factors): ?FailureReason
    {
        try {
            $this->guard->assertRemovable($identity, $application, LockedFactors::withId($factorId, $factors), $factors);
        } catch (OperationRefusedException $exception) {
            return $exception->reason;
        }

        return null;
    }

    /**
     * Under the lock: resolve the caller again and check the removal again on
     * the factors as stored, carrying out only those refusals, then make the
     * change.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $served
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $application
     * @param  mixed  $factorId
     * @param  \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemovalResult
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\RefusedUnderLockException
     * @throws \Throwable
     */
    private function removeUnderLock(Caller $served, ProofBinding $binding, string $application, mixed $factorId, Collection $factors): FactorRemovalResult
    {
        [$identity, $factor] = RefusedUnderLockException::carrying(function () use ($served, $binding, $application, $factorId, $factors): array {

            $caller = $this->callers->still($served, null, $binding);

            if ($caller === null) {
                throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The sign-in changed before the identity\'s lock was held.');
            }

            return [$caller->identity, $this->guard->assertRemovable($caller->identity, $application, LockedFactors::withId($factorId, $factors), $factors, $binding->sessionId)];
        });

        return $this->removal->remove($identity, $application, $factor, $factors, $binding->sessionId, $served->client);
    }

    /**
     * A new instance of the configured factor model.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
     */
    private function factorModel(): EloquentFactor&Model
    {
        $model = ConfiguredModels::factor($this->config);

        return new $model;
    }
}
