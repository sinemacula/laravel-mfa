<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchOutcome;
use Benchmarks\Support\InMemoryFactor;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;

/**
 * A soft hot path: every refused request summarises each factor it offers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FactorSummaryBench
{
    /** @var \Benchmarks\Support\InMemoryFactor */
    private InMemoryFactor $totpFactor;

    /** @var \Benchmarks\Support\InMemoryFactor */
    private InMemoryFactor $emailFactor;

    /** @var \Benchmarks\Support\InMemoryFactor */
    private InMemoryFactor $smsFactor;

    /**
     * One factor per shipped driver type, each proved to mask its destination.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        $this->totpFactor = new InMemoryFactor(
            type: 'totp',
            label : 'Authy',
        );

        $this->emailFactor = new InMemoryFactor(
            type   : 'email',
            label    : 'Primary email',
            destination: 'somebody@example.com',
        );

        $this->smsFactor = new InMemoryFactor(
            type   : 'sms',
            label    : 'Work phone',
            destination: '+441234567890',
        );

        BenchOutcome::assert('factor summary', FactorSummary::fromFactor($this->totpFactor)->maskedDestination === null);

        foreach ([$this->emailFactor, $this->smsFactor] as $factor) {
            $masked = FactorSummary::fromFactor($factor)->maskedDestination;

            BenchOutcome::assert('factor summary', $masked !== null && $masked !== $factor->getDestination());
        }
    }

    /**
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchFromTotpFactor(): void
    {
        FactorSummary::fromFactor($this->totpFactor);
    }

    /**
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchFromEmailFactor(): void
    {
        FactorSummary::fromFactor($this->emailFactor);
    }

    /**
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchFromSmsFactor(): void
    {
        FactorSummary::fromFactor($this->smsFactor);
    }

    /**
     * @return void
     */
    #[Iterations(3)]
    #[Revs(1000)]
    public function benchJsonSerialize(): void
    {
        FactorSummary::fromFactor($this->emailFactor)->jsonSerialize();
    }
}
