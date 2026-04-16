<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

/**
 * SMS gateway contract.
 *
 * Single-method contract for dispatching outbound SMS messages to a
 * recipient phone number. Implemented by consumers against their chosen
 * SMS provider (Twilio, Vonage, AWS SNS, in-house gateway, etc.) and
 * bound against this interface in a service provider. The package ships
 * a `NullSmsGateway` default that fails loud when the SMS factor driver
 * tries to issue a challenge without a real gateway bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface SmsGateway
{
    /**
     * Send the given message to the given E.164-formatted phone number.
     *
     * Implementations are expected to translate their SDK-specific
     * failure modes into exceptions — a non-throwing return implies the
     * handoff to the downstream provider succeeded.
     *
     * @param  string  $to
     * @param  string  $message
     * @return void
     */
    public function send(
        string $to,
        #[\SensitiveParameter]
        string $message,
    ): void;
}
