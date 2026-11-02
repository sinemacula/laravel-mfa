<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * A passkey gateway for tests: lists the credential ids it is given, answers
 * every assertion with the one it is given (against a non-empty allowlist and
 * response only, unless told to ignore either, as a faulty gateway would), and
 * keeps what it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FakePasskeyGateway implements PasskeyGateway
{
    /** @var list<list<string>> The allowlists of the assertions requested, oldest first. */
    public array $requested = [];

    /** @var list<list<string>> The allowlists of the assertions verified, oldest first. */
    public array $verified = [];

    /**
     * Constructor.
     *
     * @param  list<string>  $registered
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion  $assertion
     * @param  bool  $available
     * @param  bool  $checksAllowlist
     * @param  bool  $checksResponse
     * @param  ?\SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     */
    public function __construct(

        /** The credential ids of the identity's registered passkeys. */
        public array $registered = [],

        /** What every verified assertion observed, or why it did not verify. */
        public FailureReason|PasskeyAssertion $assertion = FailureReason::INVALID_CODE,

        /** Whether passkeys can be used. */
        public bool $available = true,

        /** Whether an empty allowlist verifies nothing, as it must. */
        public bool $checksAllowlist = true,

        /** Whether an empty response verifies nothing, as it must. */
        public bool $checksResponse = true,

        /** What a verification is refused with, when it cannot verify at all. */
        public ?OperationRefusedException $refusal = null,
    ) {}

    /**
     * Whether passkeys can be used.
     *
     * @return bool
     */
    #[\Override]
    public function isAvailable(): bool
    {
        return $this->available;
    }

    /**
     * The registered credential ids.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    #[\Override]
    public function credentialIds(MultiFactorAuthenticatable $identity): array
    {
        return $this->registered;
    }

    /**
     * Keep the allowlist, and return options naming it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @return array<string, mixed>
     */
    #[\Override]
    public function requestAssertion(MultiFactorAuthenticatable $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds): array
    {
        $this->requested[] = $credentialIds;

        return ['challenge' => 'fake-challenge', 'session' => $binding->sessionId, 'allowCredentials' => $credentialIds];
    }

    /**
     * Keep the allowlist, and answer the fixed assertion for a non-empty
     * allowlist and response; otherwise an invalid code.
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
        $this->verified[] = $credentialIds;

        if ($this->refusal !== null) {
            throw $this->refusal;
        }

        return ($this->checksAllowlist && $credentialIds === []) || ($this->checksResponse && $response === []) ? FailureReason::INVALID_CODE : $this->assertion;
    }
}
