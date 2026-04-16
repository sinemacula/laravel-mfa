<?php

declare(strict_types = 1);

namespace Benchmarks;

use PhpBench\Attributes as Bench;
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;

/**
 * Hot-path benchmarks for the TOTP driver.
 *
 * `verify()` is the most frequent call site — every MFA-gated request
 * that carries a fresh code runs through it — so regressions here are
 * the most visible. `issueChallenge()` is a no-op for TOTP so we don't
 * benchmark it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[Bench\BeforeMethods('setUp')]
final class TotpDriverBench
{
    /** @var \SineMacula\Laravel\Mfa\Drivers\TotpDriver */
    private TotpDriver $driver;

    /** @var \Benchmarks\InMemoryFactor */
    private InMemoryFactor $factor;

    /** @var string */
    private string $code = '';

    /**
     * Build the driver and reusable factor double once per benchmark
     * subject lifetime.
     *
     * @return void
     */
    public function __construct()
    {
        $this->driver = new TotpDriver(window: 1);
        $this->factor = new InMemoryFactor(driver: 'totp');
    }

    /**
     * Generate a fresh TOTP secret + current code before each
     * iteration so verify-hit benches always operate on a valid code.
     *
     * @return void
     */
    public function setUp(): void
    {
        $google = new Google2FA;
        $secret = $google->generateSecretKey();

        $this->factor->secret = $secret;
        $this->code           = $google->getCurrentOtp($secret);
    }

    /**
     * Measure the cost of a successful TOTP verify.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyHit(): void
    {
        $this->driver->verify($this->factor, $this->code);
    }

    /**
     * Measure the cost of a mismatched TOTP verify.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyMiss(): void
    {
        $this->driver->verify($this->factor, '000000');
    }
}
