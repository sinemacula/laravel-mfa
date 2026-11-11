<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Delivers codes through the bound `EmailSender`, which lays out the message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EmailDriver extends AbstractCodeDriver
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\EmailSender  $sender
     */
    public function __construct(

        /** Throws by default until the application binds one. */
        private readonly EmailSender $sender,
    ) {}

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::EMAIL;
    }

    /**
     * Trimmed and lower-cased, or null when not an address.
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
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sender->send($message);
    }
}
