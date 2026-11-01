<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Container\Container;
use Illuminate\Mail\Mailable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;

/**
 * Unit tests for `FakeEmailSender`: it binds itself, keeps every message
 * instead of sending it, and reads them and their codes back by address.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeEmailSender::class)]
final class FakeEmailSenderTest extends TestCase
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
     * Messages are kept in order, read back by address with the last code each
     * carried, and forgotten on reset.
     *
     * @return void
     */
    public function testMessagesAreKeptAndTheirCodesReadBack(): void
    {
        $fake   = new FakeEmailSender;
        $first  = new MfaCodeMessage('111111', 10);
        $other  = new MfaCodeMessage('222222', 10);
        $second = new MfaCodeMessage('333333', 10);
        $plain  = new Mailable;

        self::assertSame([], $fake->sent());
        self::assertNull($fake->lastCodeTo('ada@example.test'));

        $fake->send('ada@example.test', $first);
        $fake->send('bob@example.test', $other);
        $fake->send('ada@example.test', $second);
        $fake->send('ada@example.test', $plain);

        self::assertSame([
            ['to' => 'ada@example.test', 'message' => $first],
            ['to' => 'bob@example.test', 'message' => $other],
            ['to' => 'ada@example.test', 'message' => $second],
            ['to' => 'ada@example.test', 'message' => $plain],
        ], $fake->sent());
        self::assertSame([
            ['to' => 'ada@example.test', 'message' => $first],
            ['to' => 'ada@example.test', 'message' => $second],
            ['to' => 'ada@example.test', 'message' => $plain],
        ], $fake->sentTo('ada@example.test'));
        self::assertSame('333333', $fake->lastCodeTo('ada@example.test'));
        self::assertSame('222222', $fake->lastCodeTo('bob@example.test'));
        self::assertNull($fake->lastCodeTo('eve@example.test'));

        $fake->reset();

        self::assertSame([], $fake->sent());
    }

    /**
     * The last code to an address is read past any message after it that
     * carries none, and past any before it.
     *
     * @return void
     */
    public function testTheLastCodeIsReadPastOtherMessages(): void
    {
        $fake = new FakeEmailSender;

        $fake->send('ada@example.test', new Mailable);
        $fake->send('ada@example.test', new MfaCodeMessage('444444', 10));
        $fake->send('ada@example.test', new Mailable);

        self::assertSame('444444', $fake->lastCodeTo('ada@example.test'));
    }
}
