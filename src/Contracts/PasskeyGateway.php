<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Passkey gateway contract.
 *
 * The WebAuthn side of passkeys used as a factor: listing the identity's
 * registered passkeys, and requesting and verifying an assertion restricted to
 * the credentials this package has associated with the identity as factors.
 * Verification checks a challenge bound to the session, the application and the
 * purpose, the relying party and origin of the application, the signature, that
 * the credential belongs to the identity, and the sign counter (a synced
 * passkey reporting zero is not refused), and returns what was observed, never
 * what was requested.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PasskeyGateway
{
    /**
     * Whether passkeys can be used at all; when they cannot, the passkey type
     * is never offered.
     *
     * @return bool
     */
    public function isAvailable(): bool;

    /**
     * The credential ids of the identity's registered passkeys.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    public function credentialIds(MultiFactorAuthenticatable $identity): array;

    /**
     * The options of an assertion request for the identity, bound as the
     * binding says and limited to the given credentials, for the client.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @return array<string, mixed>
     */
    public function requestAssertion(MultiFactorAuthenticatable $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds): array;

    /**
     * Verify the client's response to an assertion request, limited to the
     * given credentials, and return what it observed, or why it does not
     * verify, which is counted as a failed attempt: `invalid_code` for an
     * assertion that does not hold, `expired` for a ceremony that has ended and
     * `replayed` for one already answered. A gateway that cannot verify at all
     * refuses by throwing an `OperationRefusedException`, which counts nothing.
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
