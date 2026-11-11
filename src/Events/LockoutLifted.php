<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when a lockout is lifted before it ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LockoutLifted extends ContextEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     * @param  ?\SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor unlocked, or null when the identity is. */
        public ?FactorSummary $factor = null,

        /** Who took the action, when it was someone other than the identity. */
        public ?Actor $actor = null,
    ) {
        parent::__construct($context);
    }
}
