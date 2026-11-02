<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Database\AfterStorageCommit;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;

/**
 * The default `PendingCompletion` and `StepUp`, for a package with no
 * authentication layer: a verified proof is recorded in the bound `ProofStore`.
 *
 * It refuses a failed result, and a binding whose owner, application or session
 * is not the store's current sign-in, and for a pending session not the pending
 * context's either, or whose purpose the session cannot take, with an
 * `OperationRefusedException` as `not_accepted`, so everything the verification
 * did rolls back. It never begins a sign-in: an application that binds its own
 * `PendingSessionResolver` alone begins the store's sign-in under the pending
 * id through `GuardHooks::signedIn()`.
 *
 * The proof is handed to the store once the storage connection's transaction
 * commits, and never when it rolls back, because a write to the Laravel session
 * cannot roll back. A store that refuses it then throws `ProofRefusedException`
 * from the commit, with the code spent; that is not an ordinary refusal, and is
 * not turned into one.
 *
 * Stateless: the store is resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofStoreCompletion implements PendingCompletion, StepUp
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the store and the request's caller are resolved from. */
        private Container $container,
    ) {}

    /**
     * Record a successful verification on the pending session, whose sign-in
     * the store must hold under the pending session's public id: a proof made
     * for the sign-in, or an additional factor confirmed by its enrolment.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(PendingContext $pending, VerificationResult $result): null
    {
        $proof = self::proofOf($result);

        $purpose = $proof->binding->purpose;

        OperationRefusedException::unless(
            ($purpose === Purpose::SIGN_IN || ($purpose === Purpose::ENROLLMENT && $proof->kind === ProofKind::ADDITIONAL_FACTOR))
                && ProofOwner::of($pending->identity)->ownsSignIn($proof->binding, $pending->application, $pending->sessionId),
            FailureReason::NOT_ACCEPTED,
            'The proof is not bound to the pending session.',
        );

        $this->record($pending->identity, $proof);

        return null;
    }

    /**
     * Record a successful verification on the active session of the person the
     * request serves.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function stepUp(VerificationResult $result): null
    {
        $proof    = self::proofOf($result);
        $identity = $this->container->make(CallerContextResolver::class)->resolve(null)?->identity;

        OperationRefusedException::unless(
            $identity !== null && in_array($proof->binding->purpose, [Purpose::STEP_UP, Purpose::SIGN_IN], true),
            FailureReason::NOT_ACCEPTED,
            'The proof is not one an active session can take.',
        );

        $this->record($identity, $proof);

        return null;
    }

    /**
     * Record the proof once the storage connection commits, refusing one bound
     * anywhere but the identity's current sign-in in the store.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $store       = $this->container->make(ProofStore::class);
        $application = $proof->binding->application;
        $session     = $store->currentSession($identity, $application);

        OperationRefusedException::unless(
            $session !== null && ProofOwner::of($identity)->ownsSignIn($proof->binding, $application, $session),
            FailureReason::NOT_ACCEPTED,
            'The proof is not bound to the identity\'s current sign-in.',
        );

        AfterStorageCommit::run($this->container, static fn () => $store->record($proof));
    }

    /**
     * The proof of a successful result, refusing a failed one.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private static function proofOf(VerificationResult $result): Proof
    {
        return $result->proof ?? throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'A failed verification proves nothing.');
    }
}
