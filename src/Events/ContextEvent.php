<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Contracts\MfaEvent;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * Base of the package's events. None carries a model, secret, code,
 * provisioning URI or full destination, so a queued listener can serialise it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class ContextEvent implements MfaEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     */
    public function __construct(

        /** Who and what the event is about. */
        public array $context,
    ) {}

    /**
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function context(): array
    {
        return $this->context;
    }

    /**
     * Null for a change made outside any verification.
     *
     * @return ?\SineMacula\Laravel\Mfa\Enums\Purpose
     */
    #[\Override]
    public function purpose(): ?Purpose
    {
        return null;
    }
}
