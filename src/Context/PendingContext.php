<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Support\IdentityType;

/**
 * A sign-in still owing a requirement, resolved from a pending credential the
 * authentication layer validated. Every proof must be bound to this identity,
 * application and session.
 *
 * The credential is kept for a layer that revalidates or completes the session,
 * and hidden from dumps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingContext
{
    /** @var \SensitiveParameterValue Hidden from dumps. */
    private \SensitiveParameterValue $credential;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $sessionId
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Enums\PendingAction>  $actions
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  ?string  $credential
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The identity signing in. */
        public MultiFactorAuthenticatable $identity,

        /** The application the session is for. */
        public string $application,

        /** Public id. */
        public string $sessionId,

        /** The proof that started the sign-in. */
        public Proof $firstFactor,

        /** What the session still owes. */
        public Requirement $requirement,

        /** The actions the pending credential allows. */
        public array $actions,

        /** A bootstrap enrolment grant lives no longer than this. */
        public CarbonImmutable $expiresAt,

        /** Further proofs, oldest first. */
        public array $proofs = [],

        // The pending credential, when the resolver keeps it.
        #[\SensitiveParameter]
        ?string $credential = null,
    ) {
        $this->credential = new \SensitiveParameterValue($credential);

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
     * @return ?string
     */
    public function credential(): ?string
    {
        /** @var ?string */
        return $this->credential->getValue();
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Enums\PendingAction  $action
     * @return bool
     */
    public function allows(PendingAction $action): bool
    {
        return in_array($action, $this->actions, true);
    }

    /**
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
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return bool
     */
    private function isBoundHere(ProofBinding $binding): bool
    {
        $key = $this->identity->getAuthIdentifier();

        if (!is_string($key) && !is_int($key)) {
            return false;
        }

        return (new ProofOwner(IdentityType::of($this->identity), (string) $key))->ownsSignIn($binding, $this->application, $this->sessionId);
    }

    /**
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
