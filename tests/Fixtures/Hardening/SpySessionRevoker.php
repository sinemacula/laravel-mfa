<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Hardening;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;

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
     * @param  ?\Closure(): void  $onRevokeOthers
     */
    public function __construct(

        /** The log the calls go to. */
        private LockOrderRecorder $recorder,

        /** The revoker the calls are passed to, if any. */
        private ?SessionRevoker $wrapped = null,

        /** What else happens as the identity's other sessions are revoked. */
        private ?\Closure $onRevokeOthers = null,
    ) {}

    /**
     * Note the call and pass it on.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    #[\Override]
    public function revokeOthers(MultiFactorAuthenticatable $identity): void
    {
        if ($this->onRevokeOthers !== null) {
            ($this->onRevokeOthers)();
        }

        if ($this->wrapped === null) {
            $this->recorder->seam('revokeOthers');

            return;
        }

        $this->wrapped->revokeOthers($identity);

        $this->recorder->seam('revokeOthers');
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
