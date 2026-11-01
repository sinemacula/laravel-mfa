<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Mail\Mailable;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;

/**
 * An email sender for tests: keeps every message it is given instead of
 * delivering it, so a test can read the code a request sent and verify with it.
 *
 * `FakeEmailSender::fake()` binds a fresh instance as the application's sender
 * and returns it; the manager builds its drivers again, so one resolved before
 * sends through the fake too. Not for production use.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeEmailSender implements EmailSender
{
    /** @var list<array{to: string, message: \Illuminate\Contracts\Mail\Mailable}> The messages sent, oldest first. */
    private array $sent = [];

    /**
     * Bind a fresh fake as the email sender in the container (the
     * application's, when none is given) and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        FakeSenderBinding::bind($container, EmailSender::class, $fake);

        return $fake;
    }

    /**
     * Keep the message instead of delivering it.
     *
     * @param  string  $address
     * @param  \Illuminate\Contracts\Mail\Mailable  $message
     * @return void
     */
    #[\Override]
    public function send(string $address, Mailable $message): void
    {
        $this->sent[] = [
            'to'      => $address,
            'message' => $message,
        ];
    }

    /**
     * Every message sent, oldest first.
     *
     * @return list<array{to: string, message: \Illuminate\Contracts\Mail\Mailable}>
     */
    public function sent(): array
    {
        return $this->sent;
    }

    /**
     * The messages sent to the address, oldest first.
     *
     * @param  string  $address
     * @return list<array{to: string, message: \Illuminate\Contracts\Mail\Mailable}>
     */
    public function sentTo(string $address): array
    {
        return array_values(array_filter($this->sent, static fn (array $entry): bool => $entry['to'] === $address));
    }

    /**
     * The code last sent to the address in a `MfaCodeMessage`, or `null` when
     * none was.
     *
     * @param  string  $address
     * @return ?string
     */
    public function lastCodeTo(string $address): ?string
    {
        $code = null;

        foreach ($this->sentTo($address) as $entry) {
            if (!$entry['message'] instanceof MfaCodeMessage) {
                continue;
            }

            $code = $entry['message']->code;
        }

        return $code;
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
