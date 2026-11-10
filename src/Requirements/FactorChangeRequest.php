<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Database\Eloquent\Collection;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\FactorChange;

/**
 * One change the bound `Contracts\FactorChangeGate` is asked to authorise: the
 * identity and the application it acts on, the sign-in it is made from (the
 * session id its proofs are bound to), the change, the factor a removal names,
 * the requirement the application configures for the change's operation, and
 * the identity's factors as stored under its lock.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorChangeRequest
{
    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  \Illuminate\Database\Eloquent\Collection<int, covariant \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor>  $factors
     * @param  ?string  $factorId
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     *
     * @formatter:on
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity whose factors change. */
        public MultiFactorAuthenticatable $identity,

        /** The application acting. */
        public string $application,

        /** The sign-in the change is made from: the session id its proofs are bound to. */
        public string $session,

        /** The change. */
        public FactorChange $change,

        /** The identity's factors, as stored under its lock. */
        public Collection $factors,

        /** The factor a removal names, and `null` for every other change. */
        public ?string $factorId = null,

        /** The requirement the application configures for the change's operation, if any. */
        public ?Requirement $requirement = null,
    ) {
        if (trim($session) === '') {
            throw new \InvalidArgumentException('A factor change is made from a sign-in, so its session id must not be blank.');
        }

        if ($change->namesFactor() !== ($factorId !== null)) {
            throw new \InvalidArgumentException(sprintf('The change [%s] %s.', $change->value, $change->namesFactor() ? 'needs a factor' : 'names no factor'));
        }
    }
}
