<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * The package's own wording of a code sent by SMS, for an application's
 * `SmsSender` that keeps it: the `mfa::messages.sms_code` line in the current
 * locale, or the shipped English when the line lacks its `:code` placeholder,
 * with the code put in after the translator has answered, so the code never
 * reaches the translator.
 *
 * The text carries the code in clear, so it is handled as the code is: never
 * logged, and encrypted wherever it is queued.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SmsCodeText
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The text of the SMS carrying the message's code.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return string
     */
    public static function of(#[\SensitiveParameter] CodeMessage $message): string
    {
        return str_replace(ConsumerMessages::CODE_PLACEHOLDER, $message->code->reveal(), ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));
    }
}
