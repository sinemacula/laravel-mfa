<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\Login;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Begins a new sign-in in the proof store whenever Laravel's `Login` event
 * fires for an identity that can hold factors, on the application the event's
 * guard acts for and named by a fresh random id, so nothing the identity proved
 * there before, on this session or a reused one, carries over, and its sign-ins
 * on other applications are left alone. The guard's event carries no first
 * factor: the application's declared first factor, or a bound first factor
 * resolver, stands for it.
 *
 * An identity whose key cannot name a record holds no proofs, so it is left
 * alone rather than failing the sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class BeginSignInOnLogin
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofService  $proofs
     */
    public function __construct(

        /** The proof service the sign-in is begun through. */
        private ProofService $proofs,
    ) {}

    /**
     * Handle the `Login` event.
     *
     * @param  \Illuminate\Auth\Events\Login  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __invoke(Login $event): void
    {
        if (!$event->user instanceof MultiFactorAuthenticatable) {
            return;
        }

        try {
            $this->proofs->beginSignIn($event->user, $event->guard);
        } catch (UnsupportedIdentifierException) {
            return;
        }
    }
}
