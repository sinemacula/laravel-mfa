<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The default `PasskeyGateway`: this package stores no WebAuthn credentials and
 * runs no ceremonies, so without an authentication layer, or an application's
 * own binding, passkeys are unavailable. No identity has a registered passkey,
 * verifying an assertion is refused, counting nothing, and asking for one is a
 * programming error. The package refuses to boot with an application that
 * enables the `passkey` type while this gateway is still bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UnavailablePasskeyGateway implements PasskeyGateway
{
    /**
     * Passkeys cannot be used.
     *
     * @return bool
     */
    #[\Override]
    public function isAvailable(): bool
    {
        return false;
    }

    /**
     * No registered passkeys.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    #[\Override]
    public function credentialIds(MultiFactorAuthenticatable $identity): array
    {
        return [];
    }

    /**
     * Refuse: there is no ceremony to start.
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
     * Refuse: nothing can verify, and nobody tried a wrong assertion.
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
