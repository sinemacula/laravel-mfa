<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * The package's own named operations, each with a requirement and a maximum age
 * for the proof that satisfies it, checked as step-up before the change is
 * made. An application names its own operations alongside these.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Operation: string
{
    // Enrolling a further factor
    case ADD_FACTOR = 'mfa.add_factor';

    // Replacing a factor, such as rebinding its secret or destination
    case REPLACE_FACTOR = 'mfa.replace_factor';

    // Removing a factor
    case REMOVE_FACTOR = 'mfa.remove_factor';

    // Generating a new recovery code set
    case GENERATE_RECOVERY_CODES = 'mfa.generate_recovery_codes';
}
