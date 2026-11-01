<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * One thing a requirement may ask for. Each part is met or not on its own, and
 * may carry its own maximum age for the proof that satisfies it; the values are
 * the requirement codes an application words.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RequirementPart: string
{
    // An accepted additional verification, or a multi-factor first factor
    case ADDITIONAL_VERIFICATION = 'additional_verification';

    // Multifactor authentication: distinct factor categories, or one
    // multi-factor authenticator
    case MULTIFACTOR = 'multifactor';

    // At least a given assurance level
    case MINIMUM_LEVEL = 'minimum_level';

    // A phishing-resistant proof
    case PHISHING_RESISTANCE = 'phishing_resistance';
}
