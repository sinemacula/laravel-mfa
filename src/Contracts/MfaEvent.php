<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * Implemented by every event the package dispatches, so one listener can take
 * them all (`Event::listen(MfaEvent::class, ...)`) and attribute each through
 * the same context.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface MfaEvent
{
    /**
     * Who and what the event is about, as scalar values under the keys of
     * `Events\EventContext::KEYS`: the identity, principal, active tenant,
     * application, session and request; `null` for one not known.
     *
     * @return array<string, int|string|null>
     */
    public function context(): array;
}
