<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Mail\Factory;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * Opt-in `EmailSender` over Laravel's default mailer, using the
 * `mfa.codes.mailable` class. The mailer is resolved per send so the boot-time
 * configuration check builds no transport.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MailEmailSender implements EmailSender
{
    /**
     * @param  \Illuminate\Contracts\Mail\Factory  $mail
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Mail manager. */
        private Factory $mail,

        /** Read on every send. */
        private Repository $config,
    ) {}

    /**
     * Send in the code's locale unless the mailable set its own.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $minutes  = max(1, (int) ceil(($message->expiresAt->getTimestamp() - CarbonImmutable::now()->getTimestamp()) / 60));
        $mailable = (new CodeSettings($this->config))->mailable();

        $mail = new $mailable($message->code->reveal(), $minutes);

        if ($mail->locale === null) {
            $mail->locale(ConsumerMessages::locale());
        }

        $this->mail->mailer()->to($message->destination())->send($mail);
    }
}
