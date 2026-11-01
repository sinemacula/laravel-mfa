<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use Illuminate\Contracts\Mail\Mailable;

/**
 * Email sender contract.
 *
 * Delivers a message carrying a code to an email address through the
 * application's own mail set-up: the package ships no provider. An exception it
 * throws is the delivery's failure. The message carries the code: one that is
 * queued keeps it encrypted, and it is never logged.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EmailSender
{
    /**
     * Send the message to the address.
     *
     * @param  string  $address
     * @param  \Illuminate\Contracts\Mail\Mailable  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] string $address, #[\SensitiveParameter] Mailable $message): void;
}
