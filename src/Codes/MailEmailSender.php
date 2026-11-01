<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Mail\Factory;
use Illuminate\Contracts\Mail\Mailable;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

/**
 * An email sender over Laravel's mailer, for an application that binds it to
 * `EmailSender`: the message goes to the address through the default mailer,
 * queued when the message class is queueable. The package's `MfaCodeMessage`
 * encrypts its payload whenever it is queued.
 *
 * The mailer is looked up from the mail manager only when a message is sent, so
 * building the sender, as the configuration check does on every request, builds
 * no mail transport.
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
     * @param  \Illuminate\Contracts\Mail\Factory  $mail
     */
    public function __construct(

        /** The mail manager whose default mailer the message is sent through. */
        private Factory $mail,
    ) {}

    /**
     * Send the message to the address.
     *
     * @param  string  $address
     * @param  \Illuminate\Contracts\Mail\Mailable  $message
     * @return void
     */
    #[\Override]
    public function send(#[\SensitiveParameter] string $address, #[\SensitiveParameter] Mailable $message): void
    {
        $this->mail->mailer()->to($address)->send($message);
    }
}
