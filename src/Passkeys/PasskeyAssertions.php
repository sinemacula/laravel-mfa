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
 * Passkey ceremonies for `Verification`, each allowing exactly one credential:
 * never an empty or wider allowlist. Attempts and proofs are recorded by the
 * caller.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasskeyAssertions
{
    /** @var string The factor type of a passkey. */
    public const string TYPE = 'passkey';

    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Context\SessionFirstFactor  $firstFactors
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations  $associations
     */
    public function __construct(

        /** Resolves the gateway and the combination policy per call. */
        private Container $container,

        /** Reads the session's first factor. */
        private SessionFirstFactor $firstFactors,

        /** The association records. */
        private PasskeyAssociations $associations,
    ) {}

    /**
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
     * Checks the factor again under the lock. An assertion for another
     * credential fails as an invalid code.
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
     * Whether passkeys are available, the association matches and the gateway
     * still lists the credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function canTakePart(MultiFactorAuthenticatable $identity, string $application, EloquentFactor&Model $factor): bool
    {
        return $this->gateway()->isAvailable()
            && $this->isAssociated($identity, $factor)
            && in_array($factor->getCredentialReference(), $this->registered($identity, $application), true);
    }

    /**
     * The one credential a ceremony may allow. The combination policy check
     * keeps the passkey that started a sign-in from being its second factor.
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
            in_array($credential, $this->registered($identity, $binding->application), true),
            FailureReason::NOT_FOUND,
            'The passkey gateway no longer lists the factor\'s credential.',
        );

        $firstFactor = $this->firstFactors->forBinding($identity, $binding, $pending);
        $accepted    = $firstFactor !== null && $this->container->make(CombinationPolicy::class)->accepts($firstFactor, new Channel(ChannelKind::PASSKEY, $credential));

        OperationRefusedException::byPackageUnless($accepted, FailureReason::NOT_ACCEPTED, 'The combination policy does not accept the passkey after the session\'s first factor.');

        return $credential;
    }

    /**
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
     * Canonical ids only; any other encoding is left out.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function registered(MultiFactorAuthenticatable $identity, string $application): array
    {
        return array_values(array_filter($this->gateway()->credentialIds($identity, $application), CredentialId::isCanonical(...)));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gateway(): PasskeyGateway
    {
        return $this->container->make(PasskeyGateway::class);
    }
}
