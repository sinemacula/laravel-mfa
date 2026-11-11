<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\VerificationBenchHarness;
use PhpBench\Attributes\AfterMethods;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;

/**
 * Whole verifications on in-memory SQLite and the cheapest bcrypt cost; a real
 * database and hashing cost dominate, so these are not isolated overhead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AfterMethods('finish')]
#[Iterations(10)]
#[Revs(1)]
final class VerificationBench
{
    /** @var ?\Benchmarks\Support\VerificationBenchHarness */
    private ?VerificationBenchHarness $harness = null;

    /**
     * @return void
     */
    public function arrangeTotpHit(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::TOTP_HIT);
    }

    /**
     * @return void
     */
    public function arrangeTotpMiss(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::TOTP_MISS);
    }

    /**
     * @return void
     */
    public function arrangeCodeHit(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::CODE_HIT);
    }

    /**
     * @return void
     */
    public function arrangeCodeMiss(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::CODE_MISS);
    }

    /**
     * @return void
     */
    public function arrangeRecoveryCodeHit(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::RECOVERY_CODE_HIT);
    }

    /**
     * @return void
     */
    public function arrangeRecoveryCodeMiss(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::RECOVERY_CODE_MISS);
    }

    /**
     * Prove the timed call's outcome and release the clock.
     *
     * @return void
     */
    public function finish(): void
    {
        $this->harness()->finish();
    }

    /**
     * @return void
     */
    #[BeforeMethods('arrangeTotpHit')]
    public function benchTotpHit(): void
    {
        $this->harness()->run();
    }

    /**
     * @return void
     */
    #[BeforeMethods('arrangeTotpMiss')]
    public function benchTotpMiss(): void
    {
        $this->harness()->run();
    }

    /**
     * @return void
     */
    #[BeforeMethods('arrangeCodeHit')]
    public function benchCodeHit(): void
    {
        $this->harness()->run();
    }

    /**
     * @return void
     */
    #[BeforeMethods('arrangeCodeMiss')]
    public function benchCodeMiss(): void
    {
        $this->harness()->run();
    }

    /**
     * Checks the whole set.
     *
     * @return void
     */
    #[BeforeMethods('arrangeRecoveryCodeHit')]
    public function benchRecoveryCodeHit(): void
    {
        $this->harness()->run();
    }

    /**
     * Checks the whole set.
     *
     * @return void
     */
    #[BeforeMethods('arrangeRecoveryCodeMiss')]
    public function benchRecoveryCodeMiss(): void
    {
        $this->harness()->run();
    }

    /**
     * @return \Benchmarks\Support\VerificationBenchHarness
     *
     * @throws \LogicException
     */
    private function harness(): VerificationBenchHarness
    {
        return $this->harness ?? throw new \LogicException('The subject arranged no branch.');
    }
}
