<?php

declare(strict_types = 1);

namespace Benchmarks;

use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Mfa\Support\FactorSummary;

/**
 * Benchmarks for `FactorSummary::fromFactor()` and its JSON
 * serialisation.
 *
 * Exercised on every `MfaRequiredException` / `MfaExpiredException`
 * emission, which runs once per gated request against each of the
 * user's registered factors — so this is a soft hot path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class FactorSummaryBench
{
    private InMemoryFactor $totpFactor;
    private InMemoryFactor $emailFactor;
    private InMemoryFactor $smsFactor;

    public function __construct()
    {
        $this->totpFactor = new InMemoryFactor(
            driver: 'totp',
            label: 'Authy',
        );

        $this->emailFactor = new InMemoryFactor(
            driver: 'email',
            label: 'Primary email',
            recipient: 'somebody@example.com',
        );

        $this->smsFactor = new InMemoryFactor(
            driver: 'sms',
            label: 'Work phone',
            recipient: '+441234567890',
        );
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchFromTotpFactor(): void
    {
        FactorSummary::fromFactor($this->totpFactor);
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchFromEmailFactor(): void
    {
        FactorSummary::fromFactor($this->emailFactor);
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchFromSmsFactor(): void
    {
        FactorSummary::fromFactor($this->smsFactor);
    }

    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchJsonSerialize(): void
    {
        FactorSummary::fromFactor($this->emailFactor)->jsonSerialize();
    }
}
