<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Assurance\Authenticator;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;

/**
 * What every new proof goes through, under the identity's lock, wherever it was
 * made: refused unless it is itself accepted after the session's first factor,
 * whatever an older proof shows; the whole requirement evaluated again with it;
 * whether it supplies or completes the multifactor evidence of that first
 * factor with it, when the evidence is its own and not the first factor's
 * alone; and the result handed to `PendingCompletion` or `StepUp`.
 *
 * Stateless: the seams are resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProofAcceptance
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the seams are resolved from. */
        private Container $container,
    ) {}

    /**
     * Refuse a proof not accepted after the session's first factor, and
     * evaluate the session's whole requirement with it.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  list<string>  $driverAmr
     * @param  string  $type
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function evaluate(Caller $caller, Proof $proof, array $driverAmr, string $type): VerificationResult
    {
        $requirements = $this->container->make(RequirementCheck::class);
        $binding      = $proof->binding;
        $pending      = $caller->pending;
        $proofs       = $pending === null
            ? $this->container->make(SessionFirstFactor::class)->proofsOf($caller->identity, $binding->application, $binding->sessionId)
            : [$pending->firstFactor, ...self::counting($pending, $proof->generation)];
        $firstFactor = self::firstFactorOf($proofs);
        $pair        = $firstFactor === null ? null : $requirements->check(Requirement::none(), $firstFactor, $proof);

        OperationRefusedException::unless(
            $pair !== null && $pair->accepted,
            FailureReason::NOT_ACCEPTED,
            'The proof is not accepted after the session\'s first factor.',
        );

        $requirement = $pending->requirement ?? $this->container->make(RequirementService::class)->requirementFor($caller->identity, $binding->application);
        $evaluation  = $requirements->check($requirement, ...$proofs, ...[$proof]);

        $amr = array_values(array_unique(array_diff([...Authenticator::of($proof)->amr, ...$driverAmr], ['mfa'])));

        // Judged on the first factor with this proof alone, so another proof
        // the session holds cannot make it look fresh, nor the first factor
        // alone
        $refreshes = $pair->multifactorAt?->equalTo($proof->provedAt) ?? false;

        return VerificationResult::verified($proof, $evaluation, $amr, $type, $refreshes);
    }

    /**
     * Hand the result to the seam of the caller's session, as the last write of
     * the transaction, so its refusal rolls back all the change did. What the
     * seam returns is opaque to this package.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return ?object
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function handOver(Caller $caller, VerificationResult $result): ?object
    {
        return $caller->pending === null
            ? $this->container->make(StepUp::class)->stepUp($caller->context(), $result)
            : $this->container->make(PendingCompletion::class)->complete($caller->context(), $result);
    }

    /**
     * The pending session's further proofs that still count: those of the
     * current verification generation, made by now.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @param  int  $generation
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private static function counting(PendingContext $pending, int $generation): array
    {
        $now = CarbonImmutable::now();

        return array_values(array_filter($pending->proofs, static fn (Proof $proof): bool => $proof->generation === $generation && $proof->provedAt->lessThanOrEqualTo($now)));
    }

    /**
     * The session's first factor among its proofs, if it has one.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactorOf(array $proofs): ?Proof
    {
        foreach ($proofs as $proof) {
            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                return $proof;
            }
        }

        return null;
    }
}
