<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\Purpose;

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

    /**
     * What the action the event reports was for: the purpose of the attempt,
     * code or proof behind it, `enrollment` for an enrolment's events, and
     * `null` for a change made outside any verification, such as a rename, a
     * removal or a reset.
     *
     * @return ?\SineMacula\Laravel\Mfa\Enums\Purpose
     */
    public function purpose(): ?Purpose;
}
