<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when a factor is confirmed through the bootstrap path, during a
 * pending sign-in, by an identity that had none. Anyone holding the first
 * factor can take that path, so the application can tell the person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BootstrapEnrollmentCompleted extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  array<string, int|string|null>  $context
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        /** The factor, as a summary: never the model, its secret or its full destination. */
        public FactorSummary $factor,
    ) {
        parent::__construct($context);
    }
}
