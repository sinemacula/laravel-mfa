<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when an actor enables a factor through `Mfa::enableFactor()`. An
 * implicit re-enable, by another factor's success, a rebind or a reset, is not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorEnabled extends ContextEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \SineMacula\Laravel\Mfa\Events\Actor  $actor
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor as it stands once enabled. */
        public FactorSummary $factor,

        /** Who enabled it. */
        public Actor $actor,
    ) {
        parent::__construct($context);
    }
}
