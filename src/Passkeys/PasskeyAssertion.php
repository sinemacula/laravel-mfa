<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;

/**
 * What a verified passkey assertion observed: the credential that made it and
 * the properties its authenticator data showed (user presence, user
 * verification, backup eligibility and state), never what was requested; and
 * the challenge it answered, when the gateway reports one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyAssertion
{
    /**
     * Constructor.
     *
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  ?string  $challengeId
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The id of the credential that made the assertion. */
        #[\SensitiveParameter]
        public string $credentialId,

        /** The properties the assertion observed. */
        public ObservedProperties $properties,

        /** The challenge the assertion answered, for events and the proof, when the gateway reports one. */
        public ?string $challengeId = null,
    ) {
        if (trim($credentialId) === '') {
            throw new \InvalidArgumentException('The credential id of a passkey assertion must not be blank.');
        }
    }
}
