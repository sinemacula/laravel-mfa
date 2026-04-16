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
class SmsDriver extends AbstractOtpDriver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsGateway  $gateway
     * @param  string  $messageTemplate
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     */
    public function __construct(
        private readonly SmsGateway $gateway,
        private readonly string $messageTemplate = 'Your verification code is: :code',
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
    ) {
        parent::__construct($codeLength, $expiry, $maxAttempts);
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
    protected function dispatch(
        EloquentFactor $factor,
        #[\SensitiveParameter]
        string $code,
    ): void {
        $recipient = $factor->getRecipient();

        if ($recipient === null || $recipient === '') {
            throw new MissingRecipientException('SMS factor has no recipient configured; cannot deliver code.');
        }

        $message = str_replace(':code', $code, $this->messageTemplate);

        $this->gateway->send($recipient, $message);
    }
}
