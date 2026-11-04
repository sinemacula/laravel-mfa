<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\RemovalRevocation;

/**
 * A session revoker that notes each call and then runs what it wraps, if
 * anything, noting it once more when it wraps something, so what a default seam
 * of the package's own writes stays apart from what happens after it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SpySessionRevoker implements SessionRevoker
{
    /**
     * Constructor.
     *
     * @param  \Tests\Fixtures\Hardening\LockOrderRecorder  $recorder
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $wrapped
     * @param  ?\Closure(): void  $onFactorRemoved
     */
    public function __construct(

        /** The log the calls go to. */
        private LockOrderRecorder $recorder,

        /** The revoker the calls are passed to, if any. */
        private ?SessionRevoker $wrapped = null,

        /** What else happens as the identity's other sessions are revoked for a factor's removal. */
        private ?\Closure $onFactorRemoved = null,
    ) {}

    /**
     * Note the call and pass it on.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\RemovalRevocation
     */
    #[\Override]
    public function factorRemoved(MultiFactorAuthenticatable $identity, string $factorId, string $session): RemovalRevocation
    {
        if ($this->onFactorRemoved !== null) {
            ($this->onFactorRemoved)();
        }

        if ($this->wrapped === null) {
            $this->recorder->seam('factorRemoved');

            return RemovalRevocation::othersEnded();
        }

        $revocation = $this->wrapped->factorRemoved($identity, $factorId, $session);

        $this->recorder->seam('factorRemoved');

        return $revocation;
    }

    /**
     * Note the call and pass it on.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    #[\Override]
    public function revokeAll(MultiFactorAuthenticatable $identity): void
    {
        $this->wrapped?->revokeAll($identity);

        $this->recorder->seam('revokeAll');
    }
}
