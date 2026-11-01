<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * Dispatched when a recovery code is redeemed, with how many of the set remain
 * unused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RecoveryCodeUsed extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  int  $remaining
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** How many codes of the set remain unused. */
        public int $remaining,
    ) {
        parent::__construct($context);
    }
}
