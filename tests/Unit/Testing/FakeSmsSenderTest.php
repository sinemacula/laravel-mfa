<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Codes\CodeMessages;

/**
 * Unit tests for `FakeSmsSender`: it binds itself, keeps every message instead
 * of sending it, and reads them back by phone number.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeSmsSender::class)]
final class FakeSmsSenderTest extends TestCase
{
    /**
     * `fake()` binds a fresh sender in the container given, or in the global
     * container, and returns it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFakeBindsAFreshSender(): void
    {
        $container = new Container;
        $fake      = FakeSmsSender::fake($container);

        self::assertSame($fake, $container->make(SmsSender::class));
        self::assertNotSame($fake, FakeSmsSender::fake($container));

        $previous = Container::getInstance();
        $global   = new Container;

        try {
            Container::setInstance($global);

            self::assertSame(FakeSmsSender::fake(), $global->make(SmsSender::class));
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * Messages are kept in order, read back by phone number with the last code
     * each carried, and forgotten on reset.
     *
     * @return void
     */
    public function testMessagesAreKeptAndReadBack(): void
    {
        $fake   = new FakeSmsSender;
        $first  = CodeMessages::to('+447700900123', '111111', type: 'sms');
        $other  = CodeMessages::to('+447700900456', '222222', type: 'sms');
        $second = CodeMessages::to('+447700900123', '333333', type: 'sms');

        self::assertSame([], $fake->sent());
        self::assertNull($fake->lastCodeTo('+447700900123'));

        $fake->send($first);
        $fake->send($other);
        $fake->send($second);

        self::assertSame([$first, $other, $second], $fake->sent());
        self::assertSame([$first, $second], $fake->sentTo('+447700900123'));
        self::assertSame('333333', $fake->lastCodeTo('+447700900123'));
        self::assertSame([], $fake->sentTo('+447700900999'));

        $fake->reset();

        self::assertSame([], $fake->sent());
    }
}
