<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Illuminate\Contracts\Mail\Mailable;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;

/**
 * The email sender the package binds until the application binds its own: it
 * sends nothing and throws, so a code is never dropped silently. The package
 * refuses to boot with an application that enables `email` while it is bound.
 * `MailEmailSender` delivers through Laravel's mailer for an application that
 * binds it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NullEmailSender implements EmailSender
{
    /**
     * Refuse to send, naming the contract to bind.
     *
     * @param  string  $address
     * @param  \Illuminate\Contracts\Mail\Mailable  $message
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException
     */
    #[\Override]
    public function send(string $address, Mailable $message): void
    {
        throw SenderNotConfiguredException::for(EmailSender::class);
    }
}
