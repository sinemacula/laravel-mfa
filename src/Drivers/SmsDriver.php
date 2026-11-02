<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Drivers;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Codes\CodeSettings;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * SMS factor driver.
 *
 * Delivers each code to the factor's phone number in the configured message
 * through the application's `SmsSender`. The default sender throws until the
 * application binds one, so a code is never dropped silently.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SmsDriver extends AbstractCodeDriver
{
    /** @var string Placeholder in the message template, replaced with the code. */
    private const string CODE_PLACEHOLDER = CodeSettings::CODE_PLACEHOLDER;

    /** @var string The form a phone number takes: E.164, with its country code. */
    private const string E164 = '/^\+[1-9]\d{7,14}$/D';

    /**
     * Constructor.
     *
     * The message template is taken as given: the shipped driver is built from
     * `mfa.codes.sms_message`, which the package checks carries the
     * `CODE_PLACEHOLDER` when it boots (see `Codes\CodeSettings`).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SmsSender  $sender
     * @param  string  $messageTemplate
     */
    public function __construct(

        /** The sender the message is delivered through. */
        private readonly SmsSender $sender,

        /** Message template; the code replaces its `CODE_PLACEHOLDER`. */
        private readonly string $messageTemplate = 'Your verification code is: ' . self::CODE_PLACEHOLDER,
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
     * Get the configured message template.
     *
     * @return string
     */
    public function getMessageTemplate(): string
    {
        return $this->messageTemplate;
    }

    /**
     * Deliver the message carrying the code to the phone number.
     *
     * @param  string  $destination
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] string $destination, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void
    {
        $this->sender->send($destination, str_replace(self::CODE_PLACEHOLDER, $code, $this->messageTemplate));
    }
}
