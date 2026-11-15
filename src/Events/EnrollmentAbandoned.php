<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

use SineMacula\Laravel\Mfa\Enums\AbandonmentCause;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * Dispatched when an enrolment is abandoned before it was confirmed. Its
 * pending factor is gone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentAbandoned extends EnrollmentEvent
{
    /**
     * @param  array<string, int|string|null>  $context
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\AbandonmentCause  $cause
     * @param  ?\SineMacula\Laravel\Mfa\Events\Actor  $actor
     */
    public function __construct(

        // Who and what the event is about.
        array $context,

        // The pending factor, as a summary.
        FactorSummary $factor,

        /** Why it was abandoned. */
        public AbandonmentCause $cause,

        /** Who abandoned it, when it was someone other than the identity. */
        public ?Actor $actor = null,
    ) {
        parent::__construct($context, $factor);
    }
}
