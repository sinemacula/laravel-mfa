<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * What a failed attempt is counted against, and so what a lockout or throttle
 * refuses. The values are stored in the attempts table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AttemptScope: string
{
    // One factor: its failures in a row, and the lockout they apply
    case FACTOR = 'factor';

    // The identity: its failures across every factor and recovery code
    case IDENTITY = 'identity';

    // The IP address the request came from, as resolved through the
    // application's trusted proxies
    case IP = 'ip';
}
