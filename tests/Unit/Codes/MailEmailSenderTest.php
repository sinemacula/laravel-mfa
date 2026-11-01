<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Mail\PendingMail;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\MailEmailSender;
use SineMacula\Laravel\Mfa\Codes\MfaCodeMessage;

/**
 * Unit tests for `MailEmailSender`: the message goes to the address through
 * Laravel's mailer.
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
     * The message is sent to the address through the mailer, once.
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

        (new MailEmailSender($mailer))->send('ada@example.test', $message);
    }
}
