<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Codes\CodeMessages;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeEmailSender::class)]
final class FakeEmailSenderTest extends TestCase
{
    /**
     * Binds in the container given, or in the global container.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFakeBindsAFreshSender(): void
    {
        $container = new Container;
        $fake      = FakeEmailSender::fake($container);

        self::assertSame($fake, $container->make(EmailSender::class));
        self::assertNotSame($fake, FakeEmailSender::fake($container));

        $previous = Container::getInstance();
        $global   = new Container;

        try {
            Container::setInstance($global);

            self::assertSame(FakeEmailSender::fake(), $global->make(EmailSender::class));
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * Kept in order, read back by address, and forgotten on reset.
     *
     * @return void
     */
    public function testMessagesAreKeptAndTheirCodesReadBack(): void
    {
        $fake   = new FakeEmailSender;
        $first  = CodeMessages::to('ada@example.test', '111111');
        $other  = CodeMessages::to('bob@example.test', '222222');
        $second = CodeMessages::to('ada@example.test', '333333');

        self::assertSame([], $fake->sent());
        self::assertNull($fake->lastCodeTo('ada@example.test'));

        $fake->send($first);
        $fake->send($other);
        $fake->send($second);

        self::assertSame([$first, $other, $second], $fake->sent());
        self::assertSame([$first, $second], $fake->sentTo('ada@example.test'));
        self::assertSame('333333', $fake->lastCodeTo('ada@example.test'));
        self::assertSame('222222', $fake->lastCodeTo('bob@example.test'));
        self::assertNull($fake->lastCodeTo('eve@example.test'));
        self::assertSame([], $fake->sentTo('eve@example.test'));

        $fake->reset();

        self::assertSame([], $fake->sent());
    }
}
