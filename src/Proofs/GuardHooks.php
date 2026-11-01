<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;

/**
 * The lifecycle hooks a guard calls when it fires neither of Laravel's `Login`
 * and `Logout` events, as a custom or stateless guard may not: `signedIn()`
 * once it has signed an identity in, with the proof of the first factor it
 * signed them in with, and `signedOut()` once it has signed them out. Both act
 * on the bound proof store.
 *
 * Signing in begins a new sign-in, named by the session id the first factor's
 * proof is bound to, forgetting every proof the identity's previous sign-in
 * left, and records the first factor. A guard that calls neither hook and fires
 * neither event leaves no sign-in, so nothing is recorded for it and no proof
 * counts: it never inherits a verification.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardHooks
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Begin the identity's sign-in and record the first factor it was signed in
     * with.
     *
     * The proof must be of the first factor at sign-in, bound to the identity,
     * and made under the identity's current verification generation (see
     * `VerificationGeneration::current()`); anything else is refused, as it
     * would never count.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function signedIn(MultiFactorAuthenticatable $identity, Proof $firstFactor): void
    {
        self::assertFirstFactorOf($identity, $firstFactor);

        $store = self::store();

        $store->begin($identity, $firstFactor->binding->sessionId);
        $store->record($firstFactor);
    }

    /**
     * End the identity's sign-in, forgetting every proof of it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function signedOut(MultiFactorAuthenticatable $identity): void
    {
        self::store()->forget($identity);
    }

    /**
     * Refuse a proof that is not of the first factor at sign-in, is bound to
     * another identity, or was not made under the identity's current
     * verification generation.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertFirstFactorOf(MultiFactorAuthenticatable $identity, Proof $firstFactor): void
    {
        if ($firstFactor->kind !== ProofKind::FIRST_FACTOR) {
            $message = 'A guard signs an identity in with a proof of kind [%s], not [%s].';

            throw new \InvalidArgumentException(sprintf($message, ProofKind::FIRST_FACTOR->value, $firstFactor->kind->value));
        }

        if (!ProofOwner::of($identity)->owns($firstFactor->binding)) {
            throw new \InvalidArgumentException('The first factor\'s proof is bound to another identity.');
        }

        if ($firstFactor->generation !== VerificationGeneration::current($identity)) {
            throw new \InvalidArgumentException('The first factor\'s proof was not made under the identity\'s current verification generation.');
        }
    }

    /**
     * The bound proof store.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function store(): ProofStore
    {
        return Container::getInstance()->make(ProofStore::class);
    }
}
