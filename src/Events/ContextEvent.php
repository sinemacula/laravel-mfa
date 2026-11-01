<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Contracts\MfaEvent;

/**
 * Base of the package's events: each carries its context, who and what it is
 * about, as scalar values (see `EventContext`), and what happened in fields of
 * its own. No event carries a model, a secret, a code, a provisioning URI or a
 * full destination, so a queued listener can serialise any of them safely.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class ContextEvent implements MfaEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     */
    public function __construct(

        /** Who and what the event is about. */
        public array $context,
    ) {}

    /**
     * Who and what the event is about.
     *
     * @return array<string, int|string|null>
     */
    #[\Override]
    public function context(): array
    {
        return $this->context;
    }
}
