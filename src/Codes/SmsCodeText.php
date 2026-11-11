<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use SineMacula\Laravel\Mfa\Support\ConsumerMessages;

/**
 * Package wording for an SMS code, from `mfa::messages.sms_code`. The code is
 * inserted after translation so it never reaches the translator; never log the
 * text and encrypt it wherever it is queued.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SmsCodeText
{
    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return string
     */
    public static function of(#[\SensitiveParameter] CodeMessage $message): string
    {
        return str_replace(ConsumerMessages::CODE_PLACEHOLDER, $message->code->reveal(), ConsumerMessages::codeLine(ConsumerMessages::SMS_CODE));
    }
}
