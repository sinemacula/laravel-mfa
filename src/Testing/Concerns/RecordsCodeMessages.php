<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Concerns;

use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Testing\FakeSenderBinding;

/**
 * What a fake sender keeps: every code message it is given, oldest first,
 * instead of delivering it, so a test can read the code a request sent and
 * verify with it, and see what else the message said. A fake using it names the
 * contract it is bound as in its `SENDER` constant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsCodeMessages
{
    /** @var list<\SineMacula\Laravel\Mfa\Codes\CodeMessage> The messages sent, oldest first. */
    private array $sent = [];

    /**
     * Bind a fresh fake as the sender in the container (the application's, when
     * none is given) and return it.
     *
     * @param  ?\Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function fake(?ContainerContract $container = null): self
    {
        $fake = new self;

        FakeSenderBinding::bind($container, self::SENDER, $fake);

        return $fake;
    }

    /**
     * Keep the message instead of delivering it.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sent[] = $message;
    }

    /**
     * Every message sent, oldest first.
     *
     * @return list<\SineMacula\Laravel\Mfa\Codes\CodeMessage>
     */
    public function sent(): array
    {
        return $this->sent;
    }

    /**
     * The messages sent to the destination, oldest first.
     *
     * @param  string  $destination
     * @return list<\SineMacula\Laravel\Mfa\Codes\CodeMessage>
     */
    public function sentTo(#[\SensitiveParameter] string $destination): array
    {
        return array_values(array_filter($this->sent, static fn (CodeMessage $message): bool => $message->destination() === $destination));
    }

    /**
     * The code last sent to the destination, or `null` when none was.
     *
     * @param  string  $destination
     * @return ?string
     */
    public function lastCodeTo(#[\SensitiveParameter] string $destination): ?string
    {
        $sent = $this->sentTo($destination);

        return $sent === [] ? null : $sent[count($sent) - 1]->code->reveal();
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
