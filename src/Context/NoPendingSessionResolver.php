<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * Without an authentication layer there are no pending sessions, so every
 * helper serves the guard's identity on an active session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoPendingSessionResolver implements PendingSessionResolver
{
    /**
     * @param  \Illuminate\Http\Request  $request
     * @return null
     */
    #[\Override]
    public function fromRequest(Request $request): null
    {
        return null;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return null
     */
    #[\Override]
    public function revalidate(PendingContext $pending): null
    {
        return null;
    }
}
