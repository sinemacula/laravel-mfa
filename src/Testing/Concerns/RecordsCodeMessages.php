<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Concerns;

use Illuminate\Contracts\Container\Container as ContainerContract;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Testing\FakeSenderBinding;

/**
 * Keeps a fake sender's code messages, oldest first, instead of delivering
 * them. The using class names its bound contract in a `SENDER` constant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsCodeMessages
{
    /** @var list<\SineMacula\Laravel\Mfa\Codes\CodeMessage> */
    private array $sent = [];

    /**
     * Bind a fresh fake into the given container, or the application's.
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
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @return void
     */
    #[\Override]
    public function send(#[\SensitiveParameter] CodeMessage $message): void
    {
        $this->sent[] = $message;
    }

    /**
     * @return list<\SineMacula\Laravel\Mfa\Codes\CodeMessage>
     */
    public function sent(): array
    {
        return $this->sent;
    }

    /**
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
     * @return void
     */
    public function reset(): void
    {
        $this->sent = [];
    }
}
