<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Implemented by every event the package dispatches, so one listener can take
 * them all.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface MfaEvent
{
    /**
     * Scalar context under the keys of `Events\EventContext::KEYS`, `null`
     * where unknown.
     *
     * @return array<string, int|string|null>
     */
    public function context(): array;

    /**
     * The purpose behind the action, `enrollment` for an enrolment's events, or
     * `null` for a change made outside any verification.
     *
     * @return ?\SineMacula\Laravel\Mfa\Enums\Purpose
     */
    public function purpose(): ?Purpose;
}
