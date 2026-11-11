<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Attempts;

use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;

/**
 * One attempt to prove a factor or recovery code. Only built from the
 * identity's own validated session, so nobody else can lock an identity out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Attempt
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?\SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  ?string  $application
     * @param  ?\SineMacula\Laravel\Mfa\Context\ClientContext  $client
     */
    public function __construct(

        /** Identity charged for the attempt. */
        public MultiFactorAuthenticatable $identity,

        /** Null for a recovery code. */
        public ?Factor $factor,

        /** Purpose. */
        public Purpose $purpose,

        /** Application key, for event context. */
        public ?string $application = null,

        /** Client, when known. */
        public ?ClientContext $client = null,
    ) {}
}
