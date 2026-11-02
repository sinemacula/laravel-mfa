<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * What authorised an enrolment to start, stored with its grant, since what may
 * confirm the factor depends on it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum EnrollmentAuthorization: string
{
    // A fresh step-up on an active session, by an identity with a factor
    case STEP_UP = 'step_up';

    // The first factor proved again on an active session, by an identity with
    // no additional factor: its authority was having none
    case REAUTHENTICATION = 'reauthentication';

    // The pending session's own first factor, by an identity with no factor
    case BOOTSTRAP = 'bootstrap';
}
