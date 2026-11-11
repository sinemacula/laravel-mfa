<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Delivers codes through the bound `SmsSender`, which writes the text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SmsDriver extends AbstractCodeDriver
{
    /** @var string E.164, with its country code. */
    private const string E164 = '/^\+[1-9]\d{7,14}$/D';

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsSender  $sender
     */
    public function __construct(

        /** Throws by default until the application binds one. */
        private readonly SmsSender $sender,
    ) {}

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::SMS;
    }

    /**
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return ['sms'];
    }

    /**
     * E.164 once spaces, dashes and parentheses are stripped; a country code is
     * never assumed.
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
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sender->send($message);
    }
}
