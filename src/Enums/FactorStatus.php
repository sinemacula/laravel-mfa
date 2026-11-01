<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * Where a factor is in its enrolment. Only a confirmed factor is offered,
 * counted as enrolled, accepted for verification or reported in the
 * authentication context; a pending factor can only be confirmed or abandoned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorStatus: string
{
    // Enrolment started, not yet confirmed by a first valid code or assertion
    case PENDING = 'pending';

    // Confirmed, and so usable
    case CONFIRMED = 'confirmed';
}
