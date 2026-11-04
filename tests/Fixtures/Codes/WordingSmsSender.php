<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\SmsCodeText;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * An SMS sender for tests that words each code as the package does, when it is
 * sent, and keeps the text instead of delivering it, as an application's sender
 * keeping the package's wording would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WordingSmsSender implements SmsSender
{
    /** @var list<array{to: string, text: string}> The texts sent, oldest first. */
    private array $sent = [];

    /**
     * Word the code and keep the text.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sent[] = ['to' => $message->destination(), 'text' => SmsCodeText::of($message)];
    }

    /**
     * The text last sent to the phone number, or `null` when none was.
     *
     * @param  string  $phoneNumber
     * @return ?string
     */
    public function lastTextTo(string $phoneNumber): ?string
    {
        $texts = array_values(array_filter($this->sent, static fn (array $sent): bool => $sent['to'] === $phoneNumber));

        return $texts === [] ? null : $texts[count($texts) - 1]['text'];
    }
}
