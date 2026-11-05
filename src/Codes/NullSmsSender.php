<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;

/**
 * The SMS sender the package binds until the application binds its own: it
 * sends nothing and throws, so a code is never dropped silently. The package
 * refuses to boot with an application that enables `sms` while it is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NullSmsSender implements SmsSender
{
    /**
     * Refuse to send, naming the contract to bind.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        throw SenderNotConfiguredException::for(SmsSender::class);
    }
}
