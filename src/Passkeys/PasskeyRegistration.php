<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * A passkey an authentication layer is registering, as it hands it to the
 * change gate before it stores it: the credential's id, what the registration
 * ceremony observed, and what the ceremony was bound to. The authentication
 * layer has verified the attestation; the gate checks the binding against its
 * caller.
 *
 * The rules are checked on construction: the credential id is canonical (see
 * `CredentialId`), and the binding is for enrolment.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class PasskeyRegistration
{
    /**
     * Constructor.
     *
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The credential's id, canonical unpadded base64url. */
        #[\SensitiveParameter]
        public string $credentialId,

        /** What the registration ceremony observed. */
        public ObservedProperties $properties,

        /** What the ceremony was bound to. */
        public ProofBinding $binding,
    ) {
        CredentialId::canonical($credentialId);

        if ($binding->purpose !== Purpose::ENROLLMENT) {
            throw new \InvalidArgumentException(sprintf('A passkey registration is bound for [%s], not [%s].', Purpose::ENROLLMENT->value, $binding->purpose->value));
        }
    }
}
