<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Drivers\AbstractCodeDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;

/**
 * A code delivery driver for tests: records every code it is asked to deliver,
 * with its destination and expiry, and throws instead when told to fail, so a
 * test can read the code sent and prove a failed delivery keeps nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingCodeDriver extends AbstractCodeDriver
{
    /** @var list<array{destination: string, code: string, expires_at: \Carbon\CarbonImmutable}> The codes delivered, oldest first. */
    public array $delivered = [];

    /** @var bool Whether the next delivery throws instead. */
    public bool $fail = false;

    /**
     * A code sent by email, as the fixture's channel.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::EMAIL;
    }

    /**
     * The code last delivered, or `null` when none was.
     *
     * @return ?string
     */
    public function lastCode(): ?string
    {
        return $this->delivered === [] ? null : $this->delivered[count($this->delivered) - 1]['code'];
    }

    /**
     * Record the code, or throw when told to fail.
     *
     * @param  string  $destination
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return void
     *
     * @throws \RuntimeException
     */
    #[\Override]
    protected function send(string $destination, #[\SensitiveParameter] string $code, CarbonImmutable $expiresAt): void
    {
        if ($this->fail) {
            throw new \RuntimeException('The transport failed.');
        }

        $this->delivered[] = ['destination' => $destination, 'code' => $code, 'expires_at' => $expiresAt];
    }
}
