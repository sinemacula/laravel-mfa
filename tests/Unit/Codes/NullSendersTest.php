<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Codes\NullEmailSender;
use SineMacula\Laravel\Mfa\Codes\NullSmsSender;
use SineMacula\Laravel\Mfa\Contracts\EmailSender;
use SineMacula\Laravel\Mfa\Contracts\SmsSender;
use SineMacula\Laravel\Mfa\Exceptions\SenderNotConfiguredException;
use Tests\Fixtures\Codes\CodeMessages;

/**
 * Unit tests for the default senders: each sends nothing and throws, naming the
 * contract the application must bind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NullSmsSender::class)]
#[CoversClass(NullEmailSender::class)]
final class NullSendersTest extends TestCase
{
    /**
     * The default SMS sender refuses, naming `SmsSender`.
     *
     * @return void
     */
    public function testTheSmsSenderRefusesNamingItsContract(): void
    {
        $this->expectException(SenderNotConfiguredException::class);
        $this->expectExceptionMessage(sprintf('No sender is bound to deliver codes: bind an implementation of %s in a service provider.', SmsSender::class));

        (new NullSmsSender)->send(CodeMessages::to('+447700900123', type: 'sms'));
    }

    /**
     * The default email sender refuses, naming `EmailSender`.
     *
     * @return void
     */
    public function testTheEmailSenderRefusesNamingItsContract(): void
    {
        $this->expectException(SenderNotConfiguredException::class);
        $this->expectExceptionMessage(sprintf('No sender is bound to deliver codes: bind an implementation of %s in a service provider.', EmailSender::class));

        (new NullEmailSender)->send(CodeMessages::to('ada@example.test'));
    }
}
