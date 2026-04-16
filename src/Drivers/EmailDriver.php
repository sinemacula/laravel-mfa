<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Illuminate\Contracts\Mail\Mailer;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Exceptions\MissingRecipientException;
use SineMacula\Laravel\Mfa\Mail\MfaCodeMessage;

/**
 * Email factor driver.
 *
 * Issues one-time codes via Laravel's mail subsystem and verifies them
 * in constant time. The shipped `MfaCodeMessage` Mailable carries an
 * inline HTML body so the package works with no published views;
 * consumers who want a branded email subclass the Mailable (or pass
 * their own Mailable class via the driver constructor) and override
 * its `content()` to point at their own view.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class EmailDriver extends AbstractOtpDriver
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Mail\Mailer  $mailer
     * @param  class-string<\SineMacula\Laravel\Mfa\Mail\MfaCodeMessage>  $mailable
     * @param  int  $codeLength
     * @param  int  $expiry
     * @param  int  $maxAttempts
     */
    public function __construct(
        private readonly Mailer $mailer,
        private readonly string $mailable = MfaCodeMessage::class,
        int $codeLength = 6,
        int $expiry = 10,
        int $maxAttempts = 3,
    ) {
        parent::__construct($codeLength, $expiry, $maxAttempts);
    }

    /**
     * Get the configured Mailable class.
     *
     * @return class-string<\SineMacula\Laravel\Mfa\Mail\MfaCodeMessage>
     */
    public function getMailable(): string
    {
        return $this->mailable;
    }

    /**
     * Dispatch the Mailable to the factor's recipient email.
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
            throw new MissingRecipientException('Email factor has no recipient configured; cannot deliver code.');
        }

        /** @var \SineMacula\Laravel\Mfa\Mail\MfaCodeMessage $message */
        $message = new ($this->mailable)($code, $this->getExpiry());

        $this->mailer->to($recipient)->send($message);
    }
}
