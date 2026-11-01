<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Base of the events an enrolment dispatches: each is about the factor being
 * enrolled, and each is for enrolment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class EnrollmentEvent extends ContextEvent
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

    /**
     * What the action the event reports was for: enrolment.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\Purpose
     */
    #[\Override]
    public function purpose(): Purpose
    {
        return Purpose::ENROLLMENT;
    }
}
