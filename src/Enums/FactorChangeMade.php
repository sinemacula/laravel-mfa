<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * A change made to an identity's factors on an active session, after which
 * `Contracts\SessionTransition` judges the session again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorChangeMade: string
{
    // A factor confirmed by its enrolment
    case CONFIRMED = 'factor_confirmed';

    // A passkey registered and associated as a factor
    case PASSKEY_REGISTERED = 'passkey_factor_registered';

    // A factor removed
    case REMOVED = 'factor_removed';
}
