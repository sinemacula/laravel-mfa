<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Mail\Mailable;
use Illuminate\Contracts\Mail\Mailer;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

/**
 * An email sender over Laravel's mailer, for an application that binds it to
 * `EmailSender`: the message goes to the address through the default mailer,
 * queued when the message class is queueable. The package's `MfaCodeMessage`
 * encrypts its payload whenever it is queued.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MailEmailSender implements EmailSender
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Mail\Mailer  $mailer
     */
    public function __construct(

        /** The mailer the message is sent through. */
        private Mailer $mailer,
    ) {}

    /**
     * Send the message to the address.
     *
     * @param  string  $address
     * @param  \Illuminate\Contracts\Mail\Mailable  $message
     * @return void
     */
    #[\Override]
    public function send(string $address, Mailable $message): void
    {
        $this->mailer->to($address)->send($message);
    }
}
