<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Applications\ApplicationSettings;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Attempts\LockedFactors;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The ceremony checks of a passkey factor, through the bound `PasskeyGateway`,
 * one factor and one credential per ceremony, for `Verification` to run.
 *
 * A ceremony is allowed exactly the credential associated with the factor, and
 * only when the factor is a confirmed passkey of the identity's, of a type the
 * application enables, its association names the same owner and credential, the
 * gateway still lists the credential among the identity's registered passkeys,
 * and the combination policy accepts it after the session's first factor, so
 * the passkey that started a sign-in is never its second factor. No ceremony is
 * ever started with an empty or wider allowlist: a credential that fails any of
 * these is refused with an `OperationRefusedException`.
 *
 * An assertion the gateway verifies for another credential than the one allowed
 * fails as an invalid code. Nothing here counts an attempt or records a proof:
 * the verification flow does both, holding the identity's factor state lock.
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
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     */
    public function __construct(

        /** The container the gateway and the policy are resolved from. */
        private Container $container,

        /** The reader of the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** The association records. */
        private PasskeyAssociations $associations,
    ) {}

    /**
     * The options of an assertion request for the identity's passkey factor,
     * bound as the binding says.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return array<string, mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function options(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, ?PendingContext $pending): array
    {
        return $this->gateway()->requestAssertion($identity, $binding, [$this->credential($identity, $factor, $binding, $pending)]);
    }

    /**
     * Check the factor again as stored under the lock, ask the gateway to
     * verify the response against its one credential, and return what it
     * observed when it verified that credential, or why it did not.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  array<string, mixed>  $response
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function check(
        MultiFactorAuthenticatable $identity,
        EloquentFactor&Model $factor,
        ProofBinding $binding,
        #[\SensitiveParameter] array $response,
        ?PendingContext $pending,
    ): FailureReason|PasskeyAssertion {
        $credential = $this->credential($identity, $factor, $binding, $pending);
        $assertion  = $this->gateway()->verifyAssertion($identity, $binding, [$credential], $response);

        if ($assertion instanceof FailureReason) {
            return $assertion;
        }

        return $assertion->credentialId === $credential ? $assertion : FailureReason::INVALID_CODE;
    }

    /**
     * Whether the factor could take part in a ceremony at all: passkeys are
     * available, its association matches, and the gateway still lists its
     * credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function canTakePart(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor): bool
    {
        return $this->gateway()->isAvailable()
            && $this->isAssociated($identity, $factor)
            && in_array($factor->getCredentialReference(), $this->registered($identity), true);
    }

    /**
     * The one credential a ceremony for the factor may allow, refusing a factor
     * that is not a confirmed passkey of an enabled type, one whose association
     * does not match it, a credential the gateway no longer lists, and one the
     * combination policy does not accept after the session's first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    private function credential(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor, ProofBinding $binding, ?PendingContext $pending): string
    {
        $credential = $factor->getCredentialReference();

        OperationRefusedException::byPackageUnless(
            $credential !== null && $this->isAssociated($identity, $factor),
            FailureReason::NOT_FOUND,
            'The factor is not a passkey associated with the identity.',
        );

        $this->refuseUnusable($factor, $binding);

        OperationRefusedException::byPackageUnless(
            in_array($credential, $this->registered($identity), true),
            FailureReason::NOT_FOUND,
            'The passkey gateway no longer lists the factor\'s credential.',
        );

        $firstFactor = $this->firstFactors->forBinding($identity, $binding, $pending);
        $accepted    = $firstFactor !== null && $this->container->make(CombinationPolicy::class)->accepts($firstFactor, new Channel(ChannelKind::PASSKEY, $credential));

        OperationRefusedException::byPackageUnless($accepted, FailureReason::NOT_ACCEPTED, 'The combination policy does not accept the passkey after the session\'s first factor.');

        return $credential;
    }

    /**
     * Whether the factor is a passkey whose association names the identity and
     * the factor's credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function isAssociated(MultiFactorAuthenticatable $identity, EloquentFactor&Model $factor): bool
    {
        $id = LockedFactors::idOf($factor);

        return $factor->getType() === self::TYPE
            && $id !== null
            && PasskeyAssociations::matches($factor, ProofOwner::of($identity), $this->associations->forFactor($id));
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
        OperationRefusedException::byPackageUnless($factor->isConfirmed(), FailureReason::NOT_CONFIRMED, 'The passkey factor is pending.');
        OperationRefusedException::byPackageUnless($factor->getDisabledAt() === null, FailureReason::LOCKED, 'The passkey factor is disabled after reaching the failure ceiling.');

        $settings = new ApplicationSettings($this->container->make(Repository::class), $binding->application);

        OperationRefusedException::byPackageUnless($settings->enables(self::TYPE), FailureReason::TYPE_NOT_ENABLED, 'The application does not enable passkeys.');
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
