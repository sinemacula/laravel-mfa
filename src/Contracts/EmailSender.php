<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;

/**
 * Delivers a code by email; an exception fails the delivery and drops the code.
 * Never log the code, and encrypt any queued payload, address included.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EmailSender
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] CodeMessage $message): void;
}
