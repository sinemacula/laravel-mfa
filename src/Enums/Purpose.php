<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * What a proof or a delivered code is for. A proof is bound to its purpose, and
 * a code issued for one purpose matches nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Purpose: string
{
    // Completing a sign-in
    case SIGN_IN = 'sign_in';

    // Proving the first factor again on an existing session
    case REAUTHENTICATE = 'reauthenticate';

    // Raising or refreshing an active session's assurance for an operation
    case STEP_UP = 'step_up';

    // Confirming a factor being enrolled
    case ENROLLMENT = 'enrollment';
}
