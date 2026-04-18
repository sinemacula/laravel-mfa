<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException;
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
 * @copyright   2026 Sine Macula Limited.
 */
final class SmsDriver extends AbstractOtpDriver
{
    /** @var string Placeholder the message template MUST carry; replaced with the issued code at dispatch. */
    private const string CODE_PLACEHOLDER = ':code';

    /**
     * Constructor.
     *
     * Validates at construction that the message template contains the
     * `CODE_PLACEHOLDER` — without it, the rendered SMS would ship the literal
     * placeholder string to users. Fail loudly at boot rather than silently
     * leaking a broken message on every challenge.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsGateway  $gateway
     * @param  string  $messageTemplate
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     * @param  ?string  $alphabet
     * @param  ?callable(int, int): int  $randomInt
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    public function __construct(

        /** SMS gateway implementation that delivers the rendered message. */
        private readonly SmsGateway $gateway,

        /** Message template; MUST contain the `CODE_PLACEHOLDER` constant. */
        private readonly string $messageTemplate = 'Your verification code is: ' . self::CODE_PLACEHOLDER,

        // The remaining parameters are passthroughs to AbstractOtpDriver.
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
        ?string $alphabet = null,
        ?callable $randomInt = null,

    ) {
        self::assertValidMessageTemplate($messageTemplate);

        parent::__construct($codeLength, $expiry, $maxAttempts, $alphabet, $randomInt);
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

    /**
     * Reject message templates missing the `CODE_PLACEHOLDER` — without it, the
     * rendered SMS would ship the literal template string to users on every
     * challenge.
     *
     * Static so the check runs before `parent::__construct()` has initialised
     * readonly properties on `$this`.
     *
     * @param  string  $template
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException
     */
    private static function assertValidMessageTemplate(string $template): void
    {
        if (!str_contains($template, self::CODE_PLACEHOLDER)) {
            throw InvalidDriverConfigurationException::templateMissingPlaceholder('SmsDriver message template', $template, self::CODE_PLACEHOLDER);
        }
    }
}
