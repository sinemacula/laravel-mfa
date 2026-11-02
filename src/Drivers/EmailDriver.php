<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * Email factor driver.
 *
 * Delivers each code to the factor's email address in the configured message
 * class (`MfaCodeMessage` or a subclass, whose queued payload is encrypted),
 * through the application's `EmailSender`. The message renders in the locale it
 * is sent in unless it chose its own, also on a queue worker. The default
 * sender throws until the application binds one.
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
     * @param  class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>  $mailable
     */
    public function __construct(

        /** The sender the message is delivered through. */
        private readonly EmailSender $sender,

        /** The message class the code is delivered in. */
        private readonly string $mailable = MfaCodeMessage::class,
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
     * Get the configured message class.
     *
     * @return class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>
     */
    public function getMailable(): string
    {
        return $this->mailable;
    }

    /**
     * Deliver the code to the address in the message class, with the whole
     * minutes, at least 1, it has left.
     *
     * @param  string  $destination
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] string $destination, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void
    {
        $minutes = max(1, (int) ceil(($expiresAt->getTimestamp() - CarbonImmutable::now()->getTimestamp()) / 60));

        $message = new ($this->mailable)($code, $minutes);

        if ($message->locale === null) {
            $message->locale(ConsumerMessages::locale());
        }

        $this->sender->send($destination, $message);
    }
}
