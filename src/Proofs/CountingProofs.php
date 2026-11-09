<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Which of a sign-in's proofs still count, by the rules every read of them
 * applies: bound to the identity, the application and the sign-in, made in the
 * identity's current verification generation, and not dated in the future. What
 * counts is returned oldest first, and proofs made at the same instant keep the
 * order they were given in.
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
     * The proofs given that count for the identity's sign-in on the
     * application, oldest first.
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
