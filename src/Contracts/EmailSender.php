<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;

/**
 * Email sender contract.
 *
 * Delivers a code to the email address the message names, through the
 * application's own mail set-up. It is given the neutral details of the code
 * (see `Codes\CodeMessage`) and lays out the message itself; the package's
 * `Codes\MailEmailSender` sends its own `MfaCodeMessage` through Laravel's
 * mailer.
 *
 * It is called while the code is drawn, inside the identity's transaction. An
 * exception it throws is the delivery's failure, and the code is then not kept.
 * The code is in clear once revealed: do not log it, and an implementation that
 * queues the message must encrypt the whole queued payload, address included. A
 * queued job that fails later cannot take back a code already reported sent.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EmailSender
{
    /**
     * Send the message's code to its address.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    public function send(#[\SensitiveParameter] CodeMessage $message): void;
}
