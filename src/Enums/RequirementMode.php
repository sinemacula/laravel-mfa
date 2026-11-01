<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * When an application requires an additional factor at sign-in: the setting the
 * default requirement policy reads from the application's configuration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RequirementMode: string
{
    // Never: an additional factor is asked for only where something else
    // requires one
    case NEVER = 'never';

    // Once the identity has a confirmed factor: optional MFA
    case ENROLLED = 'enrolled';

    // Always, so an identity with no factor enrols one or is refused
    case ALWAYS = 'always';
}
