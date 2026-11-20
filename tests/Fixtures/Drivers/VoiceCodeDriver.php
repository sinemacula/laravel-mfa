<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * A third-party delivered type that reads codes out in a call, recording each.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class VoiceCodeDriver extends AbstractCodeDriver
{
    /** @var list<array{destination: string, code: string}> Oldest first. */
    public array $calls = [];

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::SMS;
    }

    /**
     * @param  string  $destination
     * @return ?string
     */
    #[\Override]
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string
    {
        $number = str_replace([' ', '(', ')'], '', $destination);

        return $number === '' ? null : $number;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->calls[] = ['destination' => $message->destination(), 'code' => $message->code->reveal()];
    }
}
