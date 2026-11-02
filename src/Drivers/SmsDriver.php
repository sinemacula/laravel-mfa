<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * SMS factor driver.
 *
 * Delivers each code to the factor's phone number through the application's
 * `SmsSender`, in the words of the locale it is sent in: the driver holds no
 * wording, so it follows the request. The default sender throws until the
 * application binds one, so a code is never dropped silently.
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
     * Deliver the message carrying the code to the phone number, the code going
     * into the template after the translator has answered, so it never reaches
     * the translator.
     *
     * @param  string  $destination
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] string $destination, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void
    {
        $this->sender->send($destination, str_replace(ConsumerMessages::CODE_PLACEHOLDER, $code, ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE)));
    }
}
