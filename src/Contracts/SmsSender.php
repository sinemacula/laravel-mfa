<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;

/**
 * Delivers a code to an E.164 number; returning means the gateway accepted it.
 * Never log the code, and encrypt any queued payload, destination included.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SmsSender
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] CodeMessage $message): void;
}
