<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Contracts\Mail\Factory;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Mail\PendingMail;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * Unit tests for `MailEmailSender`: the message goes to the address through the
 * mail manager's default mailer, which is looked up only to send.
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

        self::assertInstanceOf(MailEmailSender::class, new MailEmailSender($mail));
    }

    /**
     * The message is sent to the address through the default mailer, once.
     *
     * @return void
     */
    public function testTheMessageIsSentToTheAddressThroughTheMailer(): void
    {
        $message = new MfaCodeMessage('123456', 10);

        /** @var \Illuminate\Mail\PendingMail&\Mockery\MockInterface $pending */
        $pending = \Mockery::mock(PendingMail::class);
        $pending->shouldReceive('send')->once()->with($message)->andReturnNull();

        /** @var \Illuminate\Contracts\Mail\Mailer&\Mockery\MockInterface $mailer */
        $mailer = \Mockery::mock(Mailer::class);
        $mailer->shouldReceive('to')->once()->with('ada@example.test')->andReturn($pending);

        /** @var \Illuminate\Contracts\Mail\Factory&\Mockery\MockInterface $mail */
        $mail = \Mockery::mock(Factory::class);
        $mail->shouldReceive('mailer')->once()->withNoArgs()->andReturn($mailer);

        (new MailEmailSender($mail))->send('ada@example.test', $message);
    }
}
