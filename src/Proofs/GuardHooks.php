<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ProofKind;

/**
 * Sign-in and sign-out hooks for a guard that fires neither `Login` nor
 * `Logout`; a guard that does neither leaves no sign-in, so no proof counts.
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
     * Begin a sign-in on the first factor's application and session, forgetting
     * the previous one there, and record the first factor.
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

        $store->begin($identity, $firstFactor->binding->application, $firstFactor->binding->sessionId);
        $store->record($identity, $firstFactor);
    }

    /**
     * End the sign-in on the application the first factor's proof was bound to,
     * forgetting every proof of it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function signedOut(MultiFactorAuthenticatable $identity, string $application): void
    {
        self::store()->forget($identity, $application);
    }

    /**
     * Refuse a proof that could never count: not a first factor, another
     * identity's, or of an older generation.
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
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function store(): ProofStore
    {
        return Container::getInstance()->make(ProofStore::class);
    }
}
