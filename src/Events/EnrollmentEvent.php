<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Base of the events an enrolment dispatches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class EnrollmentEvent extends ContextEvent
{
    /**
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

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\Purpose
     */
    #[\Override]
    public function purpose(): Purpose
    {
        return Purpose::ENROLLMENT;
    }
}
