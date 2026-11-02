<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * Machine-readable reason a verification, a code request, an enrolment or a
 * change to a factor failed, carried on a failed `VerificationResult`, on an
 * `OperationRefusedException` and on the failure events.
 *
 * Backed, so listeners count failure modes and applications word them without
 * scraping messages. The values are noun first, as in `laravel-authentication`,
 * and stable once released. The reason is what a caller may be told; why it
 * failed in detail stays internal, in the result's detail, the events and the
 * logs, so a factor that does not exist and one that belongs to someone else
 * both answer `not_found`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FailureReason: string
{
    // The code or assertion did not match
    case INVALID_CODE = 'invalid_code';

    // The code, challenge or pending enrolment outlived its lifetime, or there
    // is no live one to check against
    case EXPIRED = 'expired';

    // The code was for a TOTP time step already accepted, or was already used
    case REPLAYED = 'replayed';

    // The factor or the identity is locked out until a set time
    case LOCKED = 'locked';

    // The factor's enrolment was never confirmed, so it cannot be used
    case NOT_CONFIRMED = 'not_confirmed';

    // The combination policy does not accept the factor after the session's
    // first factor
    case NOT_ACCEPTED = 'not_accepted';

    // The application does not enable the factor's type, or recovery codes
    case TYPE_NOT_ENABLED = 'type_not_enabled';

    // The identity has no factor that could be used
    case NO_FACTOR = 'no_factor';

    // The factor, challenge or enrolment does not exist or is not the
    // identity's
    case NOT_FOUND = 'not_found';

    // No more codes may be sent for now
    case SENDING_CAPPED = 'sending_capped';

    // The identity must enrol a factor before it may go further
    case MFA_ENROLLMENT_REQUIRED = 'mfa_enrollment_required';

    // The identity is not active
    case IDENTITY_INACTIVE = 'identity_inactive';

    // The identity is a machine, which never holds factors
    case MACHINE_IDENTITY = 'machine_identity';

    // The session's authentication is not fresh enough for the change: a
    // step-up, or the first factor proved again, is needed first
    case NOT_FRESH = 'not_fresh';

    // The factor is the last one that keeps a required factor covered
    case LAST_FACTOR = 'last_factor';

    // The identity has as many factors as the application allows
    case LIMIT_REACHED = 'limit_reached';

    // The credential is associated as a factor already, so it can be neither
    // associated again nor changed in place
    case CREDENTIAL_ASSOCIATED = 'credential_associated';
}
