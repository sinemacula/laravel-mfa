<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;

/**
 * Default email sender: throws so a code is never dropped silently. Boot fails
 * when `email` is enabled while it is bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class NullEmailSender implements EmailSender
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        throw SenderNotConfiguredException::for(EmailSender::class);
    }
}
