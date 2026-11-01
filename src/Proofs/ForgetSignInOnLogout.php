<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Auth\Events\Logout;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;

/**
 * Forgets the identity's sign-in, and every proof of it, whenever Laravel's
 * `Logout` event fires for an identity that can hold factors, so whoever signs
 * in next on the same session inherits nothing.
 *
 * An identity whose key cannot name a record holds no proofs, so it is left
 * alone rather than failing the sign-out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ForgetSignInOnLogout
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
     * Handle the `Logout` event.
     *
     * @param  \Illuminate\Auth\Events\Logout  $event
     * @return void
     */
    public function __invoke(Logout $event): void
    {
        if (!$event->user instanceof MultiFactorAuthenticatable) {
            return;
        }

        try {
            $this->store->forget($event->user);
        } catch (UnsupportedIdentifierException) {
            return;
        }
    }
}
