<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Email factor driver.
 *
 * Delivers each code to the factor's email address through the application's
 * `EmailSender`, which is given the code's neutral details and lays out the
 * message itself (the package's `Codes\MailEmailSender` sends its own
 * `MfaCodeMessage`). The default sender throws until the application binds one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EmailDriver extends AbstractCodeDriver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EmailSender  $sender
     */
    public function __construct(

        /** The sender the message is delivered through. */
        private readonly EmailSender $sender,
    ) {}

    /**
     * A code sent by email to the factor's address.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::EMAIL;
    }

    /**
     * The address trimmed and in lower case, or `null` when it is not one.
     *
     * @param  string  $destination
     * @return ?string
     */
    #[\Override]
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string
    {
        $address = mb_strtolower(trim($destination));

        return filter_var($address, FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE) === false ? null : $address;
    }

    /**
     * Hand the message to the email sender.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sender->send($message);
    }
}
