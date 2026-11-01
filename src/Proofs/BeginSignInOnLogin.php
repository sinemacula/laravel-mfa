<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\Login;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Begins a new sign-in in the proof store whenever Laravel's `Login` event
 * fires for an identity that can hold factors, named by a fresh random id, so
 * nothing the identity proved before, on this session or a reused one, carries
 * over. The guard's event carries no first factor: the application's declared
 * first factor, or a bound first factor resolver, stands for it.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     */
    public function __construct(

        /** The bound proof store. */
        private ProofStore $store,
    ) {}

    /**
     * Handle the `Login` event.
     *
     * @param  \Illuminate\Auth\Events\Login  $event
     * @return void
     */
    public function __invoke(Login $event): void
    {
        if (!$event->user instanceof MultiFactorAuthenticatable) {
            return;
        }

        try {
            $this->store->begin($event->user, Str::lower((string) Str::ulid()));
        } catch (UnsupportedIdentifierException) {
            return;
        }
    }
}
