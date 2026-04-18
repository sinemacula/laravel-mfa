<?php

declare(strict_types = 1);

namespace Benchmarks;

use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;

/**
 * Hot-path benchmarks for backup-code verification.
 *
 * Uses an in-memory factor so the atomic-consume conditional UPDATE is skipped;
 * benchmarking disk roundtrips belongs in the performance suite, not here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[Bench\BeforeMethods('setUp')]
final class BackupCodeBench
{
    /** @var \SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver */
    private BackupCodeDriver $driver;

    /** @var \Benchmarks\InMemoryFactor */
    private InMemoryFactor $factor;

    /** @var string */
    private string $plaintext = 'ABCDEFGHJK';

    /**
     * Build the driver and reusable factor double once per benchmark subject
     * lifetime.
     *
     * @return void
     */
    public function __construct()
    {
        $this->driver = new BackupCodeDriver;
        $this->factor = new InMemoryFactor(driver: 'backup_code');
    }

    /**
     * Reset the factor's stored hash before each iteration so a hit benchmark
     * does not leak state across revs.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->factor->secret = $this->driver->hash($this->plaintext);
    }

    /**
     * Measure the hot-path cost of a successful backup-code verify.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyHit(): void
    {
        $this->driver->verify($this->factor, $this->plaintext);
    }

    /**
     * Measure the hot-path cost of a failed backup-code verify.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyMiss(): void
    {
        $this->driver->verify($this->factor, 'WRONGCODE1');
    }

    /**
     * Measure the cost of generating a fresh backup-code set.
     *
     * @return void
     */
    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchGenerateSet(): void
    {
        $this->driver->generateSet();
    }
}
