<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Mail\Factory;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Mail\PendingMail;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\CodeMessage;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;
use Tests\Fixtures\Codes\CodeMessages;
use Tests\Fixtures\Codes\CustomMfaCodeMessage;
use Tests\Fixtures\Testing\ExplicitLocaleCodeMessage;

/**
 * Unit tests for `MailEmailSender`: the code goes to the message's address in
 * the configured message class, with the minutes it has left and the locale it
 * was sent in, through the mail manager's default mailer, which is looked up
 * only to send.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MailEmailSender::class)]
final class MailEmailSenderTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The address the code goes to. */
    private const string ADDRESS = 'ada@example.test';

    /**
     * Put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Building the sender looks up no mailer, so it builds no mail transport.
     *
     * @return void
     */
    public function testBuildingTheSenderLooksUpNoMailer(): void
    {
        /** @var \Illuminate\Contracts\Mail\Factory&\Mockery\MockInterface $mail */
        $mail = \Mockery::mock(Factory::class);
        $mail->shouldNotReceive('mailer');

        self::assertInstanceOf(MailEmailSender::class, new MailEmailSender($mail, new Repository));
    }

    /**
     * The code goes to the message's address in the shipped message, through
     * the default mailer, once.
     *
     * @return void
     */
    public function testTheCodeIsSentToTheAddressInTheShippedMessage(): void
    {
        $sent = $this->send(CodeMessages::to(self::ADDRESS, '654321'));

        self::assertSame(MfaCodeMessage::class, $sent::class);
        self::assertSame('654321', $sent->code);
    }

    /**
     * A configured message class is the one sent.
     *
     * @return void
     */
    public function testAConfiguredMessageClassIsSent(): void
    {
        $sent = $this->send(CodeMessages::to(self::ADDRESS), CustomMfaCodeMessage::class);

        self::assertInstanceOf(CustomMfaCodeMessage::class, $sent);
    }

    /**
     * A configured class that is not a code message is refused, and nothing is
     * sent.
     *
     * @return void
     */
    public function testAConfiguredClassThatIsNoCodeMessageIsRefused(): void
    {
        /** @var \Illuminate\Contracts\Mail\Factory&\Mockery\MockInterface $mail */
        $mail = \Mockery::mock(Factory::class);
        $mail->shouldNotReceive('mailer');

        $this->expectException(\InvalidArgumentException::class);

        (new MailEmailSender($mail, self::config(\stdClass::class)))->send(CodeMessages::to(self::ADDRESS));
    }

    /**
     * Rows of `[seconds the code has left, minutes the message states]`.
     *
     * @return iterable<string, array{int, int}>
     */
    public static function lifetimes(): iterable
    {
        yield 'whole minutes' => [600, 10];
        yield 'part of a minute rounds up' => [570, 10];
        yield 'just over a minute' => [61, 2];
        yield 'under a minute is one' => [30, 1];
        yield 'already past is one' => [-5, 1];
    }

    /**
     * The message states the whole minutes, at least one, the code has left.
     *
     * @param  int  $seconds
     * @param  int  $minutes
     * @return void
     */
    #[DataProvider('lifetimes')]
    public function testTheMessageStatesTheMinutesTheCodeHasLeft(int $seconds, int $minutes): void
    {
        $now = CarbonImmutable::parse('2026-11-01 12:00:00');

        CarbonImmutable::setTestNow($now);

        $sent = $this->send(CodeMessages::to(self::ADDRESS, expiresAt: $now->addSeconds($seconds)));

        self::assertSame($minutes, $sent->expiresInMinutes);
    }

    /**
     * The message carries the current locale, so a queue worker renders it as
     * it was sent.
     *
     * @return void
     */
    public function testTheCurrentLocaleIsCaptured(): void
    {
        self::assertSame('fr', $this->sentInFrench(MfaCodeMessage::class)->locale);
    }

    /**
     * A message that chose its own locale keeps it.
     *
     * @return void
     */
    public function testAMessagesOwnLocaleIsKept(): void
    {
        self::assertSame('de', $this->sentInFrench(ExplicitLocaleCodeMessage::class)->locale);
    }

    /**
     * The message of the class given, sent while the current locale is French.
     *
     * @param  class-string<\SineMacula\Laravel\Mfa\Codes\MfaCodeMessage>  $mailable
     * @return \SineMacula\Laravel\Mfa\Codes\MfaCodeMessage
     */
    private function sentInFrench(string $mailable): MfaCodeMessage
    {
        $container = new Container;
        $previous  = Container::getInstance();

        $container->instance('translator', new Translator(new ArrayLoader, 'fr'));

        Container::setInstance($container);

        try {
            return $this->send(CodeMessages::to(self::ADDRESS), $mailable);
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * Send the message through a sender over a mailer that expects one message
     * to the address, and return the message it was handed.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\CodeMessage  $message
     * @param  ?string  $mailable
     * @return \SineMacula\Laravel\Mfa\Codes\MfaCodeMessage
     */
    private function send(CodeMessage $message, ?string $mailable = null): MfaCodeMessage
    {
        $sent = null;

        /** @var \Illuminate\Mail\PendingMail&\Mockery\MockInterface $pending */
        $pending = \Mockery::mock(PendingMail::class);
        $pending->shouldReceive('send')->once()->with(\Mockery::on(static function (mixed $mail) use (&$sent): bool {
            $sent = $mail;

            return true;
        }))->andReturnNull();

        /** @var \Illuminate\Contracts\Mail\Mailer&\Mockery\MockInterface $mailer */
        $mailer = \Mockery::mock(Mailer::class);
        $mailer->shouldReceive('to')->once()->with(self::ADDRESS)->andReturn($pending);

        /** @var \Illuminate\Contracts\Mail\Factory&\Mockery\MockInterface $mail */
        $mail = \Mockery::mock(Factory::class);
        $mail->shouldReceive('mailer')->once()->withNoArgs()->andReturn($mailer);

        (new MailEmailSender($mail, self::config($mailable)))->send($message);

        self::assertInstanceOf(MfaCodeMessage::class, $sent);

        return $sent;
    }

    /**
     * Configuration naming the message class, or none.
     *
     * @param  ?string  $mailable
     * @return \Illuminate\Config\Repository
     */
    private static function config(?string $mailable): Repository
    {
        return new Repository($mailable === null ? [] : ['mfa' => ['codes' => ['mailable' => $mailable]]]);
    }
}
