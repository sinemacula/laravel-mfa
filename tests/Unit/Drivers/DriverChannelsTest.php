<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Drivers\AuthenticatorApp;
use Tests\Fixtures\Factors\TotpStubFactor;
use Tests\TestCase;

/**
 * Unit tests for what each shipped driver states of its type: the channel kind
 * its factors travel on and the `amr` values a proof by it adds, so the
 * combination policy never infers either from a type's name, and how it
 * confirms a pending factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TotpDriver::class)]
#[CoversClass(SmsDriver::class)]
#[CoversClass(EmailDriver::class)]
final class DriverChannelsTest extends TestCase
{
    /**
     * Each driver's channel kind and `amr` values.
     *
     * @return void
     */
    public function testEachDriverStatesItsChannelKindAndAmr(): void
    {
        $drivers = [
            'totp'  => new TotpDriver(new TotpSettings(new Repository), new Container),
            'sms'   => new SmsDriver(new FakeSmsSender),
            'email' => new EmailDriver(new FakeEmailSender),
        ];

        self::assertSame([
            'totp'  => [ChannelKind::AUTHENTICATOR_APP, ['otp']],
            'sms'   => [ChannelKind::SMS, ['sms']],
            'email' => [ChannelKind::EMAIL, ['otp']],
        ], array_map(static fn (FactorDriver $driver): array => [$driver->channelKind(), $driver->amr()], $drivers));
    }

    /**
     * A TOTP factor is confirmed by the code its authenticator app shows now,
     * and not by another, nor by a factor with no secret.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATotpFactorIsConfirmedByItsCurrentCode(): void
    {
        $driver = new TotpDriver(new TotpSettings(new Repository), new Container);
        $secret = $driver->startEnrollment(new TotpStubFactor(null));
        $factor = new TotpStubFactor($secret);
        $code   = AuthenticatorApp::code($factor);

        self::assertFalse($driver->confirm($factor, $code === '000000' ? '111111' : '000000'));
        self::assertFalse($driver->confirm(new TotpStubFactor(null), $code));
        self::assertTrue($driver->confirm($factor, $code));
    }
}
