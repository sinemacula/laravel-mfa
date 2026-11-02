<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * What a verification submits, which decides the route it takes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SubmissionKind: string
{
    // A code for a factor that makes its own, such as TOTP
    case FACTOR = 'factor';

    // A code answering a challenge sent to a delivered factor
    case CHALLENGE = 'challenge';

    // A recovery code, checked against the identity's whole set
    case RECOVERY_CODE = 'recovery_code';

    // A passkey's response to an assertion request
    case ASSERTION = 'assertion';
}
