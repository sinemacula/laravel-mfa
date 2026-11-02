<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * The outcome of checking a code against the challenge sent for a factor,
 * session, application and purpose.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CodeCheck: string
{
    // The code matched the challenge's live code, which this check used up
    case ACCEPTED = 'accepted';

    // The code did not match the challenge's live code, or a resend replaced
    // the code the check read
    case INVALID = 'invalid';

    // The challenge's code has expired
    case EXPIRED = 'expired';

    // The challenge has used up its attempts
    case EXHAUSTED = 'exhausted';

    // The code matched the challenge's last code, which was already used
    case REPLAYED = 'replayed';

    // The challenge was already used, and the code is not the one that used it
    case SPENT = 'spent';

    // No code was sent for the factor, session, application and purpose, or the
    // challenge named belongs to another
    case MISSING = 'missing';

    /**
     * Why a check that did not accept the code failed, as a failure reason, or
     * `null` for one that did. A known challenge with no live code to check
     * against, whatever the cause, is `expired`; a challenge that is absent, or
     * another's, is `not_found`.
     *
     * @return ?\SineMacula\Laravel\Mfa\Enums\FailureReason
     */
    public function failure(): ?FailureReason
    {
        return match ($this) {
            self::ACCEPTED                              => null,
            self::INVALID                               => FailureReason::INVALID_CODE,
            self::REPLAYED                              => FailureReason::REPLAYED,
            self::EXPIRED, self::EXHAUSTED, self::SPENT => FailureReason::EXPIRED,
            self::MISSING                               => FailureReason::NOT_FOUND,
        };
    }

    /**
     * Why, in detail, for the internal record of a failure: events and logs,
     * never the caller.
     *
     * @return string
     */
    public function detail(): string
    {
        return match ($this) {
            self::ACCEPTED  => 'The code matched and was used.',
            self::INVALID   => 'The code did not match.',
            self::EXPIRED   => 'The code has expired.',
            self::EXHAUSTED => 'The challenge has used up its attempts.',
            self::REPLAYED  => 'The code was already used.',
            self::SPENT     => 'The challenge was already used.',
            self::MISSING   => 'No code was sent for this factor, session, application and purpose.',
        };
    }
}
