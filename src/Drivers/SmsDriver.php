<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * SMS factor driver.
 *
 * Delivers each code to the factor's phone number through the application's
 * `SmsSender`, which is given the code's neutral details and writes the text
 * itself. The default sender throws until the application binds one, so a code
 * is never dropped silently.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SmsDriver extends AbstractCodeDriver
{
    /** @var string The form a phone number takes: E.164, with its country code. */
    private const string E164 = '/^\+[1-9]\d{7,14}$/D';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsSender  $sender
     */
    public function __construct(

        /** The sender the message is delivered through. */
        private readonly SmsSender $sender,
    ) {}

    /**
     * A code sent by SMS to the factor's phone number.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::SMS;
    }

    /**
     * The `amr` value of a code sent by SMS: `sms`.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['sms'];
    }

    /**
     * The number in E.164, once spaces, dashes and parentheses are stripped, or
     * `null` when it is not one: a country code is never assumed.
     *
     * @param  string  $destination
     * @return ?string
     */
    #[\Override]
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string
    {
        $number = str_replace([' ', '-', '(', ')'], '', $destination);

        return preg_match(self::E164, $number) === 1 ? $number : null;
    }

    /**
     * Hand the message to the SMS sender.
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
