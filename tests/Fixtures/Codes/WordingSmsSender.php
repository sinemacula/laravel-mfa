<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * Words each code as the package does and keeps the text instead of delivering
 * it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WordingSmsSender implements SmsSender
{
    /** @var list<array{to: string, text: string}> Oldest first. */
    private array $sent = [];

    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sent[] = ['to' => $message->destination(), 'text' => SmsCodeText::of($message)];
    }

    /**
     * @param  string  $phoneNumber
     * @return ?string
     */
    public function lastTextTo(string $phoneNumber): ?string
    {
        $texts = array_values(array_filter($this->sent, static fn (array $sent): bool => $sent['to'] === $phoneNumber));

        return $texts === [] ? null : $texts[count($texts) - 1]['text'];
    }
}
