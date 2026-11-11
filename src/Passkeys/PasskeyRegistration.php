<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * A passkey an authentication layer has verified the attestation of and hands
 * to the change gate before storing it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PasskeyRegistration
{
    /**
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Canonical unpadded base64url. */
        #[\SensitiveParameter]
        public string $credentialId,

        /** What the ceremony observed. */
        public ObservedProperties $properties,

        /** Must be for enrolment. */
        public ProofBinding $binding,
    ) {
        CredentialId::canonical($credentialId);

        if ($binding->purpose !== Purpose::ENROLLMENT) {
            throw new \InvalidArgumentException(sprintf('A passkey registration is bound for [%s], not [%s].', Purpose::ENROLLMENT->value, $binding->purpose->value));
        }
    }
}
