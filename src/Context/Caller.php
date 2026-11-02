<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * Who a helper is serving on this request: a person, either the identity of a
 * pending session whose credential allows what the helper does, or the identity
 * the guard signed in on an active session.
 *
 * It is resolved once per call (see `CallerContextResolver`) and holds nothing
 * beyond the request it was resolved for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Caller
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     */
    public function __construct(

        /** The person being served. */
        public MultiFactorAuthenticatable $identity,

        /** The pending session the person is served on, or `null` for an active one. */
        public ?PendingContext $pending = null,
    ) {}
}
