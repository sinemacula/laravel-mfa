<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * A code to deliver: what `SmsSender::send()` and `EmailSender::send()` are
 * given, as neutral details the application words and lays out itself.
 *
 * The destination is the factor's own, in the one form it keeps (an E.164
 * number, a lower-cased address), captured under the identity's lock when the
 * code was drawn; the recipient is the identity the code is for. The code is a
 * `RevealedSecret`: reveal it only into the message to the recipient, and never
 * log it. The destination and the recipient are held as
 * `\SensitiveParameterValue`s and read through `destination()` and
 * `recipient()`, so a dump of the message shows neither them nor the code. The
 * factor's summary masks its destination, but its label is the person's own
 * text and is shown as it is.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeMessage
{
    /** @var \SensitiveParameterValue The destination, hidden from dumps. */
    private \SensitiveParameterValue $destination;

    /** @var \SensitiveParameterValue The recipient, hidden from dumps. */
    private \SensitiveParameterValue $recipient;

    /**
     * Constructor.
     *
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

        /** The application the code is for. */
        public string $application,

        /** What the code proves: a sign-in, a reauthentication, a step-up, or an enrolment. */
        public Purpose $purpose,

        /** The factor's type, such as `sms` or `email`. */
        public string $type,

        // The factor's destination, in the form it keeps.
        #[\SensitiveParameter]
        string $destination,

        /** The code. */
        public RevealedSecret $code,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,

        // The identity the code is for.
        #[\SensitiveParameter]
        MultiFactorAuthenticatable $recipient,

        /** The factor the code is sent for, its destination masked. */
        public FactorSummary $factor,
    ) {
        $this->destination = new \SensitiveParameterValue($destination);
        $this->recipient   = new \SensitiveParameterValue($recipient);
    }

    /**
     * The factor's destination, in the form it keeps.
     *
     * @return string
     */
    public function destination(): string
    {
        /** @var string */
        return $this->destination->getValue();
    }

    /**
     * The identity the code is for.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    public function recipient(): MultiFactorAuthenticatable
    {
        /** @var \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable */
        return $this->recipient->getValue();
    }
}
