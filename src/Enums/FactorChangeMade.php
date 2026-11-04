<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * A change made to an identity's factors on an active session, which the bound
 * `Contracts\SessionTransition` judges the session again after: a factor
 * confirmed by its enrolment, a passkey registered as a factor, or a factor
 * removed. Where `FactorChange` names what a gate is asked to authorise, this
 * names what was done.
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
