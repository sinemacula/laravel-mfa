<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException;

/**
 * SMS factor driver.
 *
 * Issues one-time codes through a consumer-provided `SmsGateway` and
 * verifies them in constant time. The default gateway binding is
 * `NullSmsGateway`, which throws to surface the missing provider wiring
 * to the developer rather than silently dropping codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class SmsDriver extends AbstractOtpDriver
{
    /**
     * Constructor.
     *
     * Validates at construction that the message template contains the
     * `:code` placeholder — without it, the rendered SMS would ship the
     * literal placeholder string to users. Fail loudly at boot rather
     * than silently leaking a broken message on every challenge.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsGateway  $gateway
     * @param  string  $messageTemplate
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     * @param  ?string  $alphabet
     * @param  ?callable(int, int): int  $randomInt
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** SMS gateway implementation that delivers the rendered message. */
        private readonly SmsGateway $gateway,

        /** Message template; MUST contain the `:code` placeholder. */
        private readonly string $messageTemplate = 'Your verification code is: :code',

        // The remaining parameters are passthroughs to AbstractOtpDriver.
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
        ?string $alphabet = null,
        ?callable $randomInt = null,

    ) {
        if (!str_contains($messageTemplate, ':code')) {
            throw new \InvalidArgumentException(sprintf('SmsDriver message template must contain the :code placeholder; received "%s".', $messageTemplate));
        }

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
     * Dispatch the code to the factor's recipient phone number via the
     * bound SMS gateway.
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

        $message = str_replace(':code', $code, $this->messageTemplate);

        $this->gateway->send($recipient, $message);
    }
}
