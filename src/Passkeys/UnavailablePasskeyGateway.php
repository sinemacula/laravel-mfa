<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The default `PasskeyGateway`: this package runs no WebAuthn ceremonies, so
 * passkeys are unavailable until an authentication layer binds its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UnavailablePasskeyGateway implements PasskeyGateway
{
    /**
     * @return bool
     */
    #[\Override]
    public function isAvailable(): bool
    {
        return false;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    #[\Override]
    public function credentialIds(MultiFactorAuthenticatable $identity): array
    {
        return [];
    }

    /**
     * Asking for one is a programming error.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    #[\Override]
    public function requestAssertion(MultiFactorAuthenticatable $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds): array
    {
        throw new \LogicException(sprintf('Passkeys are unavailable: bind a passkey gateway to %s.', PasskeyGateway::class));
    }

    /**
     * Refused without counting: nobody tried a wrong assertion.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @param  array<string, mixed>  $response
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    #[\Override]
    public function verifyAssertion(
        MultiFactorAuthenticatable $identity,
        ProofBinding $binding,
        #[\SensitiveParameter] array $credentialIds,
        #[\SensitiveParameter] array $response,
    ): FailureReason|PasskeyAssertion {
        throw new OperationRefusedException(FailureReason::TYPE_NOT_ENABLED, 'Passkeys are unavailable: no passkey gateway is bound.');
    }
}
