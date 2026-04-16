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
    /** @var string Stable code seeded into both factor doubles each iteration. */
    private const string CODE = '123456';

    /** @var \SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver */
    private AbstractOtpDriver $driver;

    /** @var \Benchmarks\InMemoryFactor */
    private InMemoryFactor $factorHit;

    /** @var \Benchmarks\InMemoryFactor */
    private InMemoryFactor $factorExpired;

    /**
     * Build a single SMS driver instance and the two factor doubles
     * the verify benches reuse across iterations.
     *
     * @return void
     */
    public function __construct()
    {
        $this->driver = new SmsDriver(gateway: new FakeSmsGateway);

        $this->factorHit     = new InMemoryFactor(driver: 'sms');
        $this->factorExpired = new InMemoryFactor(driver: 'sms');
    }

    /**
     * Reset the factor codes / expiries before each iteration so a
     * verify call cannot leak mutated state across runs.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->factorHit->code      = self::CODE;
        $this->factorHit->expiresAt = Carbon::now()->addMinutes(10);

        $this->factorExpired->code      = self::CODE;
        $this->factorExpired->expiresAt = Carbon::now()->subMinute();
    }

    /**
     * Measure the cost of a successful OTP verify.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyHit(): void
    {
        $this->driver->verify($this->factorHit, self::CODE);
    }

    /**
     * Measure the cost of a mismatched OTP verify.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyMiss(): void
    {
        $this->driver->verify($this->factorHit, '000000');
    }

    /**
     * Measure the cost of an expired-code verify (the early-return
     * branch).
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyExpired(): void
    {
        $this->driver->verify($this->factorExpired, self::CODE);
    }
}
