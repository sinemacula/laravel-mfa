<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;

/**
 * A pending session, a sign-in still owing a requirement, as resolved from a
 * pending credential the authentication layer has validated: the identity, the
 * application, the session's public id, the first factor's proof, the
 * outstanding requirement, the actions the credential allows, and the further
 * proofs the session already holds.
 *
 * The rules between the parts are checked on construction: the first factor's
 * proof is a first factor made at sign-in, bound to this identity, application
 * and session, each further proof is bound to them too and is no first factor,
 * and the actions are pending actions, each named once. A helper serves a
 * pending session only an action it `allows()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingContext
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity signing in. */
        public MultiFactorAuthenticatable $identity,

        /** The application the session is for. */
        public string $application,

        /** The pending session's public id. */
        public string $sessionId,

        /** The proof of the first factor that started the sign-in. */
        public Proof $firstFactor,

        /** What the session still owes. */
        public Requirement $requirement,

        /** The actions the pending credential allows. */
        public array $actions,

        /** The further proofs the session already holds, oldest first. */
        public array $proofs = [],
    ) {
        if (trim($application) === '') {
            throw new \InvalidArgumentException('The application of a pending session must not be blank.');
        }

        if (trim($sessionId) === '') {
            throw new \InvalidArgumentException('The session id of a pending session must not be blank.');
        }

        $this->assertFirstFactor();
        $this->assertProofs();
        self::assertActions($actions);
    }

    /**
     * Whether the pending credential allows the action.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return bool
     */
    public function allows(PendingAction $action): bool
    {
        return in_array($action, $this->actions, true);
    }

    /**
     * Refuse a first factor's proof that is not a first factor, or is bound to
     * another identity, application or session.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertFirstFactor(): void
    {
        if ($this->firstFactor->kind !== ProofKind::FIRST_FACTOR) {
            throw new \InvalidArgumentException(sprintf('The first factor of a pending session must be a proof of kind [%s].', ProofKind::FIRST_FACTOR->value));
        }

        if (!$this->isBoundHere($this->firstFactor->binding)) {
            throw new \InvalidArgumentException('The first factor of a pending session must be bound to its identity, application and session.');
        }
    }

    /**
     * Refuse a further proof that is not a proof, is a first factor, or is
     * bound to another identity, application or session.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertProofs(): void
    {
        foreach ($this->proofs as $proof) {

            if ($proof->kind === ProofKind::FIRST_FACTOR) {
                throw new \InvalidArgumentException('The further proofs of a pending session must not hold a first factor.');
            }

            if (!$this->isBoundHere($proof->binding)) {
                throw new \InvalidArgumentException('The further proofs of a pending session must be bound to its identity, application and session.');
            }
        }
    }

    /**
     * Whether the binding names this session's identity, application and
     * session.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    private function isBoundHere(ProofBinding $binding): bool
    {
        $key = $this->identity->getAuthIdentifier();

        return $binding->identityType === CurrentIdentity::typeOf($this->identity)
            && (is_string($key) || is_int($key))
            && $binding->identityKey === (string) $key
            && $binding->application === $this->application
            && $binding->sessionId   === $this->sessionId;
    }

    /**
     * Refuse actions that are not a list of pending actions, each named once.
     *
     * @param  array<array-key, mixed>  $actions
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertActions(array $actions): void
    {
        if (!array_is_list($actions)) {
            throw new \InvalidArgumentException('The actions of a pending session must be a list.');
        }

        foreach ($actions as $index => $action) {
            if (!$action instanceof PendingAction) {
                throw new \InvalidArgumentException(sprintf('The actions of a pending session must be %s cases; got [%s].', PendingAction::class, get_debug_type($action)));
            }

            if (array_search($action, $actions, true) !== $index) {
                throw new \InvalidArgumentException(sprintf('The pending action [%s] is named more than once.', $action->value));
            }
        }
    }
}
