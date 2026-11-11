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
 * Answers every assertion with the one it is given, for a non-empty allowlist
 * and response unless told to skip either check, and keeps what it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FakePasskeyGateway implements PasskeyGateway
{
    /** @var list<list<string>> Allowlists requested, oldest first. */
    public array $requested = [];

    /** @var list<list<string>> Allowlists verified, oldest first. */
    public array $verified = [];

    /**
     * @param  list<string>  $registered
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion  $assertion
     * @param  bool  $available
     * @param  bool  $checksAllowlist
     * @param  bool  $checksResponse
     * @param  ?\SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException  $refusal
     * @param  ?\Throwable  $requestRefusal
     */
    public function __construct(

        /** Credential ids of the identity's passkeys. */
        public array $registered = [],

        /** Every verification's answer. */
        public FailureReason|PasskeyAssertion $assertion = FailureReason::INVALID_CODE,

        /** @var bool */
        public bool $available = true,

        /** Whether an empty allowlist verifies nothing, as it must. */
        public bool $checksAllowlist = true,

        /** Whether an empty response verifies nothing, as it must. */
        public bool $checksResponse = true,

        /** Thrown by every verification. */
        public ?OperationRefusedException $refusal = null,

        /** Thrown by every assertion request. */
        public ?\Throwable $requestRefusal = null,
    ) {}

    /**
     * @return bool
     */
    #[\Override]
    public function isAvailable(): bool
    {
        return $this->available;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return list<string>
     */
    #[\Override]
    public function credentialIds(MultiFactorAuthenticatable $identity): array
    {
        return $this->registered;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  list<string>  $credentialIds
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function requestAssertion(MultiFactorAuthenticatable $identity, ProofBinding $binding, #[\SensitiveParameter] array $credentialIds): array
    {
        if ($this->requestRefusal !== null) {
            throw $this->requestRefusal;
        }

        $this->requested[] = $credentialIds;

        return ['challenge' => 'fake-challenge', 'session' => $binding->sessionId, 'allowCredentials' => $credentialIds];
    }

    /**
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
