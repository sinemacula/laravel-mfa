<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;

/**
 * What a verified passkey assertion observed, never what was requested.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyAssertion
{
    /**
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  ?string  $challengeId
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The credential that made the assertion. */
        #[\SensitiveParameter]
        public string $credentialId,

        /** From the authenticator data. */
        public ObservedProperties $properties,

        /** The challenge answered, when the gateway reports one. */
        public ?string $challengeId = null,
    ) {
        if (trim($credentialId) === '') {
            throw new \InvalidArgumentException('The credential id of a passkey assertion must not be blank.');
        }
    }
}
