<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Mail\Factory;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * An email sender over Laravel's mailer, for an application that binds it to
 * `EmailSender`: the code goes to the address in the configured message class
 * (`mfa.codes.mailable`: `MfaCodeMessage` or a subclass), with the whole
 * minutes, at least 1, it has left, through the default mailer, queued when the
 * message class is queueable. The package's `MfaCodeMessage` encrypts its
 * payload whenever it is queued. The message renders in the locale the code is
 * sent in unless it chose its own, also on a queue worker.
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
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The mail manager whose default mailer the message is sent through. */
        private Factory $mail,

        /** Configuration the message class is read from on every send. */
        private Repository $config,
    ) {}

    /**
     * Send the code to the message's address in the configured message class.
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
