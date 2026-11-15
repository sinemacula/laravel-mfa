<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * Why an enrolment was abandoned before it was confirmed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AbandonmentCause: string
{
    // A new enrolment of the same type replaced it
    case RESTARTED = 'restarted';

    // The identity cancelled it
    case CANCELED = 'canceled';

    // Its confirmation attempts ran out
    case ATTEMPTS_EXHAUSTED = 'attempts_exhausted';

    // Someone reset the identity's factors
    case RESET = 'reset';
}
