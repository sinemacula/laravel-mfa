<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * SMS sender contract.
 *
 * Delivers a message carrying a code to an E.164 phone number through the
 * application's own SMS gateway: the package ships no provider. An exception it
 * throws is the delivery's failure; a return means the gateway accepted the
 * message. The message carries the code in clear: do not log it, and an
 * implementation that queues it must encrypt the queued payload (for example,
 * with a job that implements `ShouldBeEncrypted`).
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SmsSender
{
    /**
     * Send the message to the phone number.
     *
     * @param  string  $phoneNumber
     * @param  string  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] string $phoneNumber, #[\SensitiveParameter] string $message): void;
}
