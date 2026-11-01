<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;

/**
 * An SMS sender for tests: keeps every message it is given instead of
 * delivering it, so a test can read the code a request sent and verify with it.
 *
 * `FakeSmsSender::fake()` binds a fresh instance as the application's sender
 * and returns it. Not for production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeSmsSender implements SmsSender
{
    /** @var list<array{to: string, message: string}> The messages sent, oldest first. */
    private array $sent = [];

    /**
     * Bind a fresh fake as the SMS sender in the container (the application's,
     * when none is given) and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        ($container ?? Container::getInstance())->instance(SmsSender::class, $fake);

        return $fake;
    }

    /**
     * Keep the message instead of delivering it.
     *
     * @param  string  $phoneNumber
     * @param  string  $message
     * @return void
     */
    #[\Override]
    public function send(string $phoneNumber, #[\SensitiveParameter] string $message): void
    {
        $this->sent[] = [
            'to'      => $phoneNumber,
            'message' => $message,
        ];
    }

    /**
     * Every message sent, oldest first.
     *
     * @return list<array{to: string, message: string}>
     */
    public function sent(): array
    {
        return $this->sent;
    }

    /**
     * The messages sent to the phone number, oldest first.
     *
     * @param  string  $phoneNumber
     * @return list<array{to: string, message: string}>
     */
    public function sentTo(string $phoneNumber): array
    {
        return array_values(array_filter($this->sent, static fn (array $entry): bool => $entry['to'] === $phoneNumber));
    }

    /**
     * The message last sent to the phone number, or `null` when none was.
     *
     * @param  string  $phoneNumber
     * @return ?string
     */
    public function lastMessageTo(string $phoneNumber): ?string
    {
        $sent = $this->sentTo($phoneNumber);

        return $sent === [] ? null : $sent[count($sent) - 1]['message'];
    }

    /**
     * Forget every message sent so far.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->sent = [];
    }
}
