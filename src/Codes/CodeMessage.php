<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * A code for a sender to deliver. Destination and recipient are wrapped so a
 * dump shows neither; the factor summary's label is unmasked user text.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeMessage
{
    /** @var \SensitiveParameterValue */
    private \SensitiveParameterValue $destination;

    /** @var \SensitiveParameterValue */
    private \SensitiveParameterValue $recipient;

    /**
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $type
     * @param  string  $destination
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $recipient
     * @param  \SineMacula\Laravel\Mfa\Factors\FactorSummary  $factor
     */
    public function __construct(

        /** Application key. */
        public string $application,

        /** Purpose. */
        public Purpose $purpose,

        /** Factor type, such as `sms` or `email`. */
        public string $type,

        // Normalised: E.164 number or lower-cased address.
        #[\SensitiveParameter]
        string $destination,

        /** Reveal only into the message; never log. */
        public RevealedSecret $code,

        /** Expiry time. */
        public CarbonImmutable $expiresAt,

        // Identity the code is for.
        #[\SensitiveParameter]
        MultiFactorAuthenticatable $recipient,

        /** Factor, destination masked. */
        public FactorSummary $factor,
    ) {
        $this->destination = new \SensitiveParameterValue($destination);
        $this->recipient   = new \SensitiveParameterValue($recipient);
    }

    /**
     * @return string
     */
    public function destination(): string
    {
        /** @var string */
        return $this->destination->getValue();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    public function recipient(): MultiFactorAuthenticatable
    {
        /** @var \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable */
        return $this->recipient->getValue();
    }
}
