<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
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
 * The default `PendingCompletion` and `StepUp`: records the proof in the bound
 * `ProofStore` after commit, as a session write cannot roll back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProofStoreCompletion implements PendingCompletion, StepUp
{
    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * A sign-in proof, or an additional factor confirmed by enrolment, bound to
     * the pending session's sign-in in the store.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function complete(CallerContext $caller, VerificationResult $result): null
    {
        $proof   = self::proofOf($result);
        $pending = $caller->pending;

        OperationRefusedException::unless($pending !== null, FailureReason::NOT_ACCEPTED, 'The caller has no pending session to complete.');

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
     * A step-up or sign-in proof bound to the active sign-in of the person the
     * request serves.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function stepUp(CallerContext $caller, VerificationResult $result): null
    {
        $proof    = self::proofOf($result);
        $identity = $this->container->make(CallerContextResolver::class)->resolve($caller, null)?->identity;
        $session  = $identity === null ? null : $this->container->make(ProofStore::class)->currentSession($identity, $caller->application);

        OperationRefusedException::unless(
            $identity       !== null
                && $session !== null
                && in_array($proof->binding->purpose, [Purpose::STEP_UP, Purpose::SIGN_IN], true)
                && ProofOwner::of($identity)->ownsSignIn($proof->binding, $caller->application, $session),
            FailureReason::NOT_ACCEPTED,
            'The proof is not one the caller\'s active session can take.',
        );

        $this->record($identity, $proof);

        return null;
    }

    /**
     * A store that refuses after commit throws `ProofRefusedException` with the
     * code spent, which is not turned into a refusal.
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

        AfterStorageCommit::run($this->container, static fn () => $store->record($identity, $proof));
    }

    /**
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
