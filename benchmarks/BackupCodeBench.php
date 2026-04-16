<?php

declare(strict_types = 1);

namespace Benchmarks;

use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Mfa\Drivers\BackupCodeDriver;

/**
 * Hot-path benchmarks for backup-code verification.
 *
 * Uses an in-memory factor so the atomic-consume conditional UPDATE
 * is skipped; benchmarking disk roundtrips belongs in the
 * performance suite, not here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[Bench\BeforeMethods('setUp')]
final class BackupCodeBench
{
    private BackupCodeDriver $driver;
    private InMemoryFactor $factor;
    private string $plaintext = 'ABCDEFGHJK';

    public function __construct()
    {
        $this->driver = new BackupCodeDriver;
        $this->factor = new InMemoryFactor(driver: 'backup_code');
    }

    public function setUp(): void
    {
        $this->factor->secret = $this->driver->hash($this->plaintext);
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyHit(): void
    {
        $this->driver->verify($this->factor, $this->plaintext);
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchVerifyMiss(): void
    {
        $this->driver->verify($this->factor, 'WRONGCODE1');
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(100)]
    public function benchGenerateSet(): void
    {
        $this->driver->generateSet();
    }
}
