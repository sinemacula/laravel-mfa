<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Gateways;

use SineMacula\Laravel\Mfa\Contracts\SmsGateway;
use SineMacula\Laravel\Mfa\Exceptions\SmsGatewayNotConfiguredException;

/**
 * Default SMS gateway binding.
 *
 * Fails loud when the SMS factor driver tries to issue a challenge
 * without a real gateway bound. Consumers who enable the SMS driver
 * must rebind the `SmsGateway` contract to an implementation that
 * talks to their chosen SMS provider (Twilio, Vonage, AWS SNS, etc.).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class NullSmsGateway implements SmsGateway
{
    /**
     * Throw a `SmsGatewayNotConfiguredException` to surface the missing
     * binding to the developer rather than silently dropping the
     * outbound message.
     *
     * @param  string  $to
     * @param  string  $message
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SmsGatewayNotConfiguredException
     */
    public function send(
        string $to,
        #[\SensitiveParameter]
        string $message,
    ): void {
        $msg = 'No SMS gateway is bound. Bind an implementation of '
            . 'SineMacula\Laravel\Mfa\Contracts\SmsGateway in a service '
            . 'provider before using the SMS factor driver.';

        throw new SmsGatewayNotConfiguredException($msg);
    }
}
