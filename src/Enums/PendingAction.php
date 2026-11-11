<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * What a pending session may do towards completing its sign-in.
 * `laravel-authentication` uses these exact values as its pending actions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PendingAction: string
{
    // List the factors on offer, as summaries
    case LIST_FACTORS = 'mfa.list_factors';

    // Send or resend a code to a factor
    case SEND_CODE = 'mfa.send_code';

    // Verify a factor or a recovery code
    case VERIFY = 'mfa.verify';

    // Start enrolling a first factor when the identity has none
    case START_BOOTSTRAP_ENROLLMENT = 'mfa.start_bootstrap_enrollment';

    // Confirm that enrolment, receiving its secrets and any recovery codes
    case CONFIRM_BOOTSTRAP_ENROLLMENT = 'mfa.confirm_bootstrap_enrollment';
}
