<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * Refuses every message, quoting the number and code in its exceptions and in
 * an unmarked helper's arguments, as a careless gateway client would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LeakingSmsSender implements SmsSender
{
    /**
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
