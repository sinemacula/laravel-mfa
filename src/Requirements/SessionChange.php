<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * One change to an identity's factors made on an active session, which the
 * bound `Contracts\SessionTransition` judges the session again after: the
 * identity and the application acting, the sign-in the change was made on (the
 * session id its proofs are bound to), what was done, the factor it was done
 * to, and the package's own assessment of the session, the requirement it no
 * longer meets on the proofs it holds, or `null` when it meets it.
 *
 * The assessment is information, not a verdict: a layer that judges the session
 * by rules of its own judges it whatever the assessment says.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionChange
{
    /**
     * Constructor.
     *
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

        /** The sign-in the change was made on: the session id its proofs are bound to. */
        public string $session,

        /** What was done. */
        public FactorChangeMade $change,

        /** The factor it was done to, as it stood once done. */
        public FactorSummary $factor,

        /** The requirement the session no longer meets on the proofs it holds, whole, or `null` when it meets it. */
        public ?Requirement $outstanding,
    ) {
        if (trim($session) === '') {
            throw new \InvalidArgumentException('A factor change is made on a sign-in, so its session id must not be blank.');
        }
    }
}
