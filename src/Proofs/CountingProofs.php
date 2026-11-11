<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The proofs that still count: bound to the identity, application and sign-in,
 * of the current generation and not dated in the future.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingProofs
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Oldest first, keeping the given order for proofs made at the same
     * instant.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  array<array-key, \SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function of(MultiFactorAuthenticatable $identity, string $application, string $session, array $proofs): array
    {
        $owner      = ProofOwner::of($identity);
        $generation = VerificationGeneration::current($identity);
        $now        = CarbonImmutable::now();

        $counting = array_values(array_filter(
            $proofs,
            static fn (Proof $proof): bool => $owner->ownsSignIn($proof->binding, $application, $session)
                && $proof->generation === $generation
                && $proof->provedAt->lessThanOrEqualTo($now),
        ));

        usort($counting, static fn (Proof $a, Proof $b): int => $a->provedAt <=> $b->provedAt);

        return $counting;
    }
}
