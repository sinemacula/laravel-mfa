<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException;

/**
 * SMS factor driver.
 *
 * Issues one-time codes through a consumer-provided `SmsGateway` and verifies
 * them in constant time. The default gateway binding is `NullSmsGateway`, which
 * throws to surface the missing provider wiring to the developer rather than
 * silently dropping codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SmsDriver extends AbstractOtpDriver
{
    /** @var string Placeholder in the message template, replaced with the issued code at dispatch. */
    private const string CODE_PLACEHOLDER = CodeSettings::CODE_PLACEHOLDER;

    /**
     * Constructor.
     *
     * The message template is taken as given: the shipped driver is built from
     * `mfa.codes.sms_message`, which the package checks carries the
     * `CODE_PLACEHOLDER` when it boots (see `Codes\CodeSettings`).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsGateway  $gateway
     * @param  string  $messageTemplate
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  ?callable(int, int): int  $randomInt
     */
    public function __construct(

        /** SMS gateway implementation that delivers the rendered message. */
        private readonly SmsGateway $gateway,

        /** Message template; the code replaces its `CODE_PLACEHOLDER`. */
        private readonly string $messageTemplate = 'Your verification code is: ' . self::CODE_PLACEHOLDER,

        // Generated code length; passthrough to `AbstractOtpDriver`.
        int $codeLength = 6,

        // Code lifetime in minutes; passthrough to `AbstractOtpDriver`.
        int $expiry = 10,

        // Randomness seam; passthrough to `AbstractOtpDriver`.
        ?callable $randomInt = null,
    ) {
        parent::__construct($codeLength, $expiry, $randomInt);
    }

    /**
     * Get the configured message template.
     *
     * @return string
     */
    public function getMessageTemplate(): string
    {
        return $this->messageTemplate;
    }

    /**
     * Dispatch the code to the factor's recipient phone number via the bound
     * SMS gateway.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $code
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException
     */
    #[\Override]
    protected function dispatch(EloquentFactor $factor, #[\SensitiveParameter] string $code): void
    {
        $recipient = $factor->getRecipient();

        if ($recipient === null || $recipient === '') {
            throw new MissingRecipientException('SMS factor has no recipient configured; cannot deliver code.');
        }

        $message = str_replace(self::CODE_PLACEHOLDER, $code, $this->messageTemplate);

        $this->gateway->send($recipient, $message);
    }
}
