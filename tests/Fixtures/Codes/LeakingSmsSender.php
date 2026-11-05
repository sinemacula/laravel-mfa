<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * An SMS sender for tests whose gateway refuses every message, quoting the
 * phone number and the message, code included, in the exception it throws and
 * in a previous one, as a careless gateway client would. It hands both to a
 * helper of its own that marks neither as sensitive, so PHP records them in
 * that frame's arguments.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LeakingSmsSender implements SmsSender
{
    /**
     * Refuse to send, quoting the phone number and the message.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->post($message->destination(), SmsCodeText::of($message));
    }

    /**
     * Post the message to the gateway, which refuses it.
     *
     * @param  string  $to
     * @param  string  $body
     * @return void
     *
     * @throws \RuntimeException
     */
    private function post(string $to, string $body): void
    {
        $upstream = new \RuntimeException(sprintf('Gateway said: invalid body "%s"', $body));

        throw new \RuntimeException(sprintf('The gateway refused the message to %s.', $to), 0, $upstream);
    }
}
