<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Attempts\RequestIp;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\CallerContextResolver;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Factors\OperationGuard;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Requests and verifies passkey assertions for the caller's passkey factors,
 * through the bound `PasskeyGateway`, one factor and one credential per
 * ceremony.
 *
 * A ceremony is allowed exactly the credential associated with the factor, and
 * only when the factor is a confirmed passkey of the caller's, of a type the
 * application enables, its association names the same owner and credential,
 * the gateway still lists the credential among the identity's registered
 * passkeys, and the combination policy accepts it after the session's first
 * factor, so the passkey that started a sign-in is never its second factor. No
 * ceremony is ever started with an empty or wider allowlist: a credential that
 * fails any of these is refused with an `OperationRefusedException`.
 *
 * Verifying is an attempt through `Attempts\AttemptService`: refused while a
 * lockout applies, re-checked under the identity's factor state lock, and
 * counted against the factor and the identity, so a failed assertion counts as
 * a wrong code would. An assertion the gateway verifies for another credential
 * than the one allowed fails. A verified assertion is returned with what it
 * observed, for the verification flow to record as a proof.
 *
 * Serving a pending session needs its `mfa.verify` action: without it, and
 * without a signed-in person, there is nothing to request or verify.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyAssertions
{
    /** @var string The factor type passkeys are associated as. */
    public const string TYPE = 'passkey';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContextResolver  $callers
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     * @param  \SineMacula\Laravel\Mfa\Factors\OperationGuard  $guard
     * @param  \SineMacula\Laravel\Mfa\Attempts\AttemptService  $attempts
     */
    public function __construct(

        /** The container the gateway and the policy are resolved from. */
        private Container $container,

        /** The resolver of who the request serves. */
        private CallerContextResolver $callers,

        /** The reader of the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** The association records. */
        private PasskeyAssociations $associations,

        /** The guard every operation on a factor starts with. */
        private OperationGuard $guard,

        /** The counts a verification is made through. */
        private AttemptService $attempts,
    ) {}

    /**
     * The options of an assertion request for the caller's passkey factor, for
     * the purpose given; none when the request serves nobody for verifying.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Throwable
     */
    public function requestAssertion(Factor $factor, Purpose $purpose): array
    {
        $caller = $this->callers->resolve(PendingAction::VERIFY);

        if ($caller === null) {
            return [];
        }

        $binding    = $this->binding($caller, $purpose);
        $stored     = $this->guard->factor($caller->identity, $factor->getFactorIdentifier(), $binding->application);
        $credential = $this->credential($caller->identity, $stored, $binding);

        return $this->gateway()->requestAssertion($caller->identity, $binding, [$credential]);
    }

    /**
     * Verify the client's response for the caller's passkey factor, for the
     * purpose given, and return what the assertion observed; `null` when it
     * does not verify, or when the request serves nobody for verifying.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  array<string, mixed>  $response
     * @return ?\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException
     * @throws \Throwable
     */
    public function verifyAssertion(Factor $factor, Purpose $purpose, array $response): ?PasskeyAssertion
    {
        $caller = $this->callers->resolve(PendingAction::VERIFY);

        if ($caller === null) {
            return null;
        }

        if (!LockedFactors::keepsState($factor)) {
            throw new UnsupportedFactorException('A passkey factor must be a stored EloquentFactor model.');
        }

        $identity  = $caller->identity;
        $binding   = $this->binding($caller, $purpose);
        $assertion = null;

        $outcome = $this->attempts->attempt(
            new Attempt($identity, $factor, $purpose, RequestIp::resolve($this->container), $binding->application),
            function (?Factor $stored) use ($identity, $binding, $response, &$assertion): bool {

                if (!LockedFactors::keepsState($stored)) {
                    return false;
                }

                $assertion = $this->verified($identity, $stored, $binding, $response);

                if ($assertion === null) {
                    return false;
                }

                $stored->recordVerification();
                $stored->persist();

                return true;
            },
        );

        return $outcome->passed ? $assertion : null;
    }

    /**
     * Under the lock: check the factor again, ask the gateway to verify the
     * response against its one credential, and return what it observed when
     * it verified that credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  array<string, mixed>  $response
     * @return ?\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function verified(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, array $response): ?PasskeyAssertion
    {
        $credential = $this->credential($identity, $factor, $binding);
        $assertion  = $this->gateway()->verifyAssertion($identity, $binding, [$credential], $response);

        return $assertion !== null && $assertion->credentialId === $credential ? $assertion : null;
    }

    /**
     * The one credential a ceremony for the factor may allow, refusing a
     * factor that is not a confirmed passkey of an enabled type, one whose
     * association does not match it, a credential the gateway no longer lists,
     * and one the combination policy does not accept after the session's first
     * factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function credential(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding): string
    {
        $owner      = ProofOwner::of($identity);
        $id         = LockedFactors::idOf($factor);
        $credential = $factor->getCredentialReference();

        if ($factor->getType() !== self::TYPE || $id === null || $credential === null || !PasskeyAssociations::matches($factor, $owner, $this->associations->forFactor($id))) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The factor is not a passkey associated with the identity.');
        }

        $this->refuseUnusable($factor, $binding);

        if (!in_array($credential, $this->registered($identity), true)) {
            throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The passkey gateway no longer lists the factor\'s credential.');
        }

        $firstFactor = $this->firstFactors->forBinding($identity, $binding);

        if ($firstFactor === null || !$this->container->make(CombinationPolicy::class)->accepts($firstFactor, new Channel(ChannelKind::PASSKEY, $credential))) {
            throw new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'The combination policy does not accept the passkey after the session\'s first factor.');
        }

        return $credential;
    }

    /**
     * Refuse a factor that is pending, disabled at the failure ceiling, or of a
     * type the application does not enable.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function refuseUnusable(Factor $factor, ProofBinding $binding): void
    {
        if (!$factor->isConfirmed()) {
            throw new OperationRefusedException(FailureReason::NOT_CONFIRMED, 'The passkey factor is pending.');
        }

        if ($factor->getDisabledAt() !== null) {
            throw new OperationRefusedException(FailureReason::LOCKED, 'The passkey factor is disabled after reaching the failure ceiling.');
        }

        if (!(new ApplicationSettings($this->container->make(Repository::class), $binding->application))->enables(self::TYPE)) {
            throw new OperationRefusedException(FailureReason::TYPE_NOT_ENABLED, 'The application does not enable passkeys.');
        }
    }

    /**
     * The identity's registered passkeys the gateway lists, in their canonical
     * form only: an id in any other encoding is left out.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registered(MultiFactorAuthenticatable $identity): array
    {
        return array_values(array_filter($this->gateway()->credentialIds($identity), CredentialId::isCanonical(...)));
    }

    /**
     * What the caller's ceremony is bound to, refusing a caller with no
     * session a proof could be recorded on.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\Caller  $caller
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function binding(Caller $caller, Purpose $purpose): ProofBinding
    {
        return $this->callers->binding($caller, $purpose)
            ?? throw new OperationRefusedException(FailureReason::NOT_FOUND, 'The identity has no sign-in to bind the ceremony to.');
    }

    /**
     * The bound passkey gateway.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gateway(): PasskeyGateway
    {
        return $this->container->make(PasskeyGateway::class);
    }
}
