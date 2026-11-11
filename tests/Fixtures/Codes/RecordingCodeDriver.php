<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * Records every code delivered, or throws when told to fail. `$onSend` runs
 * while the send still holds its locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCodeDriver extends AbstractCodeDriver
{
    /** @var list<array{destination: string, code: string, expires_at: \Carbon\CarbonImmutable, message: \SineMacula\Laravel\Mfa\Codes\CodeMessage}> Oldest first. */
    public array $delivered = [];

    /** @var bool Whether deliveries throw. */
    public bool $fail = false;

    /** @var (\Closure(): void)|null Runs first at each delivery. */
    public ?\Closure $onSend = null;

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::EMAIL;
    }

    /**
     * @param  string  $destination
     * @return ?string
     */
    #[\Override]
    public function normalizeDestination(#[\SensitiveParameter] string $destination): ?string
    {
        return $destination === '' ? null : $destination;
    }

    /**
     * @return ?string
     */
    public function lastCode(): ?string
    {
        return $this->delivered === [] ? null : $this->delivered[count($this->delivered) - 1]['code'];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    protected function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        if ($this->onSend !== null) {
            ($this->onSend)();
        }

        if ($this->fail) {
            throw new \RuntimeException('The transport failed.');
        }

        $this->delivered[] = ['destination' => $message->destination(), 'code' => $message->code->reveal(), 'expires_at' => $message->expiresAt, 'message' => $message];
    }
}
