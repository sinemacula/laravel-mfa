<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Gateways;

use SineMacula\Laravel\Mfa\Contracts\SmsGateway;

/**
 * In-memory test double for the SMS gateway contract.
 *
 * Records every outbound message against the gateway so tests can assert
 * dispatch without hitting a real provider. Not intended for production use;
 * tests typically rebind `SmsGateway` to an instance of this class in the
 * container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class FakeSmsGateway implements SmsGateway
{
    /** @var list<array{to: string, message: string}> */
    private array $sent = [];

    /**
     * Record the outbound message rather than dispatching it.
     *
     * @param  string  $to
     * @param  string  $message
     * @return void
     */
    #[\Override]
    public function send(string $to, #[\SensitiveParameter] string $message): void
    {
        $this->sent[] = [
            'to'      => $to,
            'message' => $message,
        ];
    }

    /**
     * Return every message the gateway has been asked to send.
     *
     * @return list<array{to: string, message: string}>
     */
    public function sent(): array
    {
        return $this->sent;
    }

    /**
     * Return only the messages sent to the given recipient.
     *
     * @param  string  $to
     * @return list<array{to: string, message: string}>
     */
    public function sentTo(string $to): array
    {
        return array_values(
            array_filter(
                $this->sent,
                static fn (array $entry): bool => $entry['to'] === $to,
            ),
        );
    }

    /**
     * Clear the recorded message log. Useful between test cases.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->sent = [];
    }
}
