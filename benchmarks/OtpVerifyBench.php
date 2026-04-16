<?php

declare(strict_types = 1);

namespace Benchmarks;

use Carbon\Carbon;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Gateways\FakeSmsGateway;

/**
 * Hot-path benchmarks for the OTP-delivery driver verification path.
 *
 * Exercised via the SMS driver, whose verify logic comes entirely
 * from `AbstractOtpDriver` — the same path the email driver takes —
 * so this bench covers both transports' verification cost.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[Bench\BeforeMethods('setUp')]
final class OtpVerifyBench
{
    private AbstractOtpDriver $driver;
    private InMemoryFactor $factorHit;
    private InMemoryFactor $factorExpired;

    public function __construct()
    {
        $this->driver = new SmsDriver(gateway: new FakeSmsGateway);

        $this->factorHit     = new InMemoryFactor(driver: 'sms');
        $this->factorExpired = new InMemoryFactor(driver: 'sms');
    }

    public function setUp(): void
    {
        $this->factorHit->code      = '123456';
        $this->factorHit->expiresAt = Carbon::now()->addMinutes(10);

        $this->factorExpired->code      = '123456';
        $this->factorExpired->expiresAt = Carbon::now()->subMinute();
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyHit(): void
    {
        $this->driver->verify($this->factorHit, '123456');
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyMiss(): void
    {
        $this->driver->verify($this->factorHit, '000000');
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyExpired(): void
    {
        $this->driver->verify($this->factorExpired, '123456');
    }
}
