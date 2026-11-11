<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * The WebAuthn side of passkeys as a factor. Verification checks the bound
 * challenge, relying party, origin, signature, credential owner and sign
 * counter (a synced passkey's zero is not refused), and returns what it
 * observed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PasskeyGateway
{
    /**
     * When `false`, the passkey type is never offered.
     *
     * @return bool
     */
    public function isAvailable(): bool;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    public function credentialIds(MultiFactorAuthenticatable $identity): array;

    /**
     * Assertion request options bound as the binding says and limited to the
     * credentials.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @return array<string, mixed>
     */
    public function requestAssertion(MultiFactorAuthenticatable $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds): array;

    /**
     * A failure (`invalid_code`, `expired`, `replayed`) counts as an attempt; a
     * gateway that cannot verify at all throws, which counts nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @param  array<string, mixed>  $response
     * @return \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException
     */
    public function verifyAssertion(
        MultiFactorAuthenticatable $identity,
        ProofBinding $binding,
        #[\SensitiveParameter] array $credentialIds,
        #[\SensitiveParameter] array $response,
    ): FailureReason|PasskeyAssertion;
}
