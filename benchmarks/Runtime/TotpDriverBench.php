<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\TotpFactor;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\Drivers\Base32;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpParameters;
use SineMacula\Laravel\Mfa\Drivers\TotpSettings;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Hot-path benchmarks for the TOTP driver.
 *
 * `verify()` is the most frequent call site, as every MFA-gated request that
 * carries a fresh code runs through it, so regressions here are the most
 * visible. It computes and compares every time step of the window whether or
 * not one matches, so a matching and a mismatched code should cost the same;
 * the factor records no step, so the cost of the database's compare-and-set is
 * not included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[BeforeMethods('setUp')]
final class TotpDriverBench
{
    /** @var \SineMacula\Laravel\Mfa\Drivers\TotpDriver */
    private TotpDriver $driver;

    /** @var \Benchmarks\Support\TotpFactor */
    private TotpFactor $factor;

    /** @var \SineMacula\Laravel\Mfa\Proofs\ProofBinding */
    private ProofBinding $binding;

    /** @var string */
    private string $code = '';

    /**
     * Build the driver, with the default settings, and a factor with a fresh
     * secret once per benchmark subject lifetime.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function __construct()
    {
        $this->driver = new TotpDriver(new TotpSettings(new Repository));
        $this->factor = new TotpFactor(Base32::encode(random_bytes(20)));

        $this->binding = new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::STEP_UP);
    }

    /**
     * Compute the factor's current code before each iteration, so the matching
     * bench always submits a code of the window.
     *
     * @return void
     */
    public function setUp(): void
    {
        $parameters = new TotpParameters('sha1', 6, 30);

        $this->code = $parameters->code(
            (string) Base32::decode($this->factor->getSecret()),
            $parameters->stepAt(CarbonImmutable::now()->getTimestamp()),
        );
    }

    /**
     * Measure the cost of verifying a code that matches a step of the window.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchVerifyHit(): void
    {
        $this->driver->verify($this->factor, $this->code, $this->binding);
    }

    /**
     * Measure the cost of a mismatched TOTP verify.
     *
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchVerifyMiss(): void
    {
        $this->driver->verify($this->factor, '000000', $this->binding);
    }
}
