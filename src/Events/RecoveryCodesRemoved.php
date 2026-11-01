<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when the identity's recovery code set is removed, as with its last
 * factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodesRemoved extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** Who took the action, when it was someone other than the identity. */
        public ?Actor $actor = null,
    ) {
        parent::__construct($context);
    }
}
