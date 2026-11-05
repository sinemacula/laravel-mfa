<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;

/**
 * SMS sender contract.
 *
 * Delivers a code to the E.164 phone number the message names, through the
 * application's own SMS gateway: the package ships no provider. It is given the
 * neutral details of the code (see `Codes\CodeMessage`) and writes the text
 * itself; `Codes\SmsCodeText::of()` gives the package's own wording.
 *
 * It is called while the code is drawn, inside the identity's transaction. An
 * exception it throws is the delivery's failure, and the code is then not
 * kept; a return means the gateway accepted the message. The code is in clear
 * once revealed: do not log it, and an implementation that queues the message
 * must encrypt the whole queued payload, destination included (for example,
 * with a job that implements `ShouldBeEncrypted`). A queued job that fails
 * later cannot take back a code already reported sent.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SmsSender
{
    /**
     * Send the message's code to its phone number.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] CodeMessage $message): void;
}
