<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * The default `PendingSessionResolver`: without an authentication layer there
 * are no pending sessions, so no request carries one. Every helper then serves
 * the identity the guard signed in, and only on an active session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoPendingSessionResolver implements PendingSessionResolver
{
    /**
     * No pending session: no request carries one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return null
     */
    #[\Override]
    public function fromRequest(Request $request): null
    {
        return null;
    }

    /**
     * No pending session stands: none was ever served.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return null
     */
    #[\Override]
    public function revalidate(PendingContext $pending): null
    {
        return null;
    }
}
