<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when a factor is given a new label.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorRenamed extends ContextEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?string  $previousLabel
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor, as a summary: never the model, its secret or its full destination. */
        public FactorSummary $factor,

        /** The label the factor had before. */
        public ?string $previousLabel = null,
    ) {
        parent::__construct($context);
    }
}
