<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\FakeSmsSender;
use Tests\Fixtures\Factors\TotpStubFactor;
use Tests\TestCase;

/**
 * The combination policy reads these, never inferring them from a type's name.
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
     * @return void
     */
    public function testEachDriverStatesItsChannelKindAndAmr(): void
    {
        $drivers = [
            'totp'  => new TotpDriver(new TotpSettings(new Repository)),
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
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATotpFactorIsConfirmedByItsCurrentCode(): void
    {
        $driver  = new TotpDriver(new TotpSettings(new Repository));
        $secret  = $driver->startEnrollment(new TotpStubFactor(null));
        $factor  = new TotpStubFactor($secret->reveal());
        $code    = AuthenticatorApp::code($factor);
        $binding = new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::ENROLLMENT);

        self::assertSame(CodeCheck::INVALID, $driver->confirm($factor, $code === '000000' ? '111111' : '000000', $binding));
        self::assertSame(CodeCheck::INVALID, $driver->confirm(new TotpStubFactor(null), $code, $binding));
        self::assertSame(CodeCheck::ACCEPTED, $driver->confirm($factor, $code, $binding));
    }
}
