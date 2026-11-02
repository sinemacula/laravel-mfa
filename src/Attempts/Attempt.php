<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * One attempt to prove a factor or a recovery code, and what it is counted
 * against: the factor and the identity. The IP address is reserved around the
 * whole verification (see `AttemptService::throttled()`).
 *
 * The identity is the one whose own pending or active session made the attempt,
 * as the caller validated it, and it is charged for the attempt: an attempt
 * made without such a session is never built, so nobody can lock an identity
 * out with requests of their own. The factor must be one of the identity's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Attempt
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?string  $application
     */
    public function __construct(

        /** The identity whose own session made the attempt, charged for it. */
        public MultiFactorAuthenticatable $identity,

        /** The identity's factor the attempt was made against, or null for a recovery code. */
        public ?Factor $factor,

        /** What the attempt was for. */
        public Purpose $purpose,

        /** The application the attempt was made through, named in the events' context. */
        public ?string $application = null,
    ) {}
}
