<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * A factor change made on an active session, for `Contracts\SessionTransition`
 * to judge; the package's assessment is information, not a verdict.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionChange
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $outstanding
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity whose factors changed. */
        public MultiFactorAuthenticatable $identity,

        /** The application acting. */
        public string $application,

        /** The session id the sign-in's proofs are bound to. */
        public string $session,

        /** What was done. */
        public FactorChangeMade $change,

        /** The factor as it stood once changed. */
        public FactorSummary $factor,

        /** The requirement the session no longer meets on its proofs, or `null`. */
        public ?Requirement $outstanding,
    ) {
        if (trim($session) === '') {
            throw new \InvalidArgumentException('A factor change is made on a sign-in, so its session id must not be blank.');
        }
    }
}
