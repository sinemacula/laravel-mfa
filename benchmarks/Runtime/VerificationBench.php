<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\VerificationBenchHarness;
use PhpBench\Attributes\AfterMethods;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;

/**
 * A whole verification through `Mfa::verify()`, hit and miss, for a TOTP code,
 * a delivered code and a recovery code: the statements, the locks and the
 * evaluation that the database-free benches leave out, on the statements the
 * query budgets count for each branch, in an address's first window for a TOTP
 * or a recovery code and in the window its send began for a delivered code.
 *
 * The results are measurements on in-memory SQLite with bcrypt at its cheapest
 * cost, with the application booted and the path warmed outside the timing;
 * they are not the package's isolated overhead, and a real database and hashing
 * cost dominate them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AfterMethods('finish')]
#[Iterations(10)]
#[Revs(1)]
final class VerificationBench
{
    /** @var ?\Benchmarks\Support\VerificationBenchHarness The branch arranged for the subject. */
    private ?VerificationBenchHarness $harness = null;

    /**
     * Arrange an accepted TOTP code.
     *
     * @return void
     */
    public function arrangeTotpHit(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::TOTP_HIT);
    }

    /**
     * Arrange a wrong TOTP code.
     *
     * @return void
     */
    public function arrangeTotpMiss(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::TOTP_MISS);
    }

    /**
     * Arrange an accepted delivered code.
     *
     * @return void
     */
    public function arrangeCodeHit(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::CODE_HIT);
    }

    /**
     * Arrange a wrong delivered code.
     *
     * @return void
     */
    public function arrangeCodeMiss(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::CODE_MISS);
    }

    /**
     * Arrange an accepted recovery code.
     *
     * @return void
     */
    public function arrangeRecoveryCodeHit(): void
    {
        $this->harness = new VerificationBenchHarness(VerificationBenchHarness::RECOVERY_CODE_HIT);
    }

    /**
     * Arrange a wrong recovery code.
     *
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
     * Measure an accepted TOTP code.
     *
     * @return void
     */
    #[BeforeMethods('arrangeTotpHit')]
    public function benchTotpHit(): void
    {
        $this->harness()->run();
    }

    /**
     * Measure a wrong TOTP code.
     *
     * @return void
     */
    #[BeforeMethods('arrangeTotpMiss')]
    public function benchTotpMiss(): void
    {
        $this->harness()->run();
    }

    /**
     * Measure an accepted delivered code.
     *
     * @return void
     */
    #[BeforeMethods('arrangeCodeHit')]
    public function benchCodeHit(): void
    {
        $this->harness()->run();
    }

    /**
     * Measure a wrong delivered code.
     *
     * @return void
     */
    #[BeforeMethods('arrangeCodeMiss')]
    public function benchCodeMiss(): void
    {
        $this->harness()->run();
    }

    /**
     * Measure an accepted recovery code, which checks the whole set.
     *
     * @return void
     */
    #[BeforeMethods('arrangeRecoveryCodeHit')]
    public function benchRecoveryCodeHit(): void
    {
        $this->harness()->run();
    }

    /**
     * Measure a wrong recovery code, which checks the whole set.
     *
     * @return void
     */
    #[BeforeMethods('arrangeRecoveryCodeMiss')]
    public function benchRecoveryCodeMiss(): void
    {
        $this->harness()->run();
    }

    /**
     * The branch arranged for the subject.
     *
     * @return \Benchmarks\Support\VerificationBenchHarness
     *
     * @throws \LogicException
     */
    private function harness(): VerificationBenchHarness
    {
        return $this->harness ?? throw new \LogicException('The subject arranged no branch.');
    }
}
