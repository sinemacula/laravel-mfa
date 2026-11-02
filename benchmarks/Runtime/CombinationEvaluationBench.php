<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchOutcome;
use Benchmarks\Support\BenchProofs;
use Carbon\CarbonImmutable;
use PhpBench\Attributes\AfterMethods;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Attributes\Revs;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Assurance\SessionProofs;

/**
 * `DefaultCombinationPolicy::evaluate()` with no database, over the proof sets
 * it decides on: a first factor and one proof, a long session, a channel the
 * first factor shares, an empty and a full requirement, and proofs either side
 * of a maximum age. Every case proves its decision at set-up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AfterMethods('releaseClock')]
#[BeforeMethods('arrange')]
final class CombinationEvaluationBench
{
    /** @var int The maximum age of the cases that have one, in seconds. */
    private const int MAX_AGE = 300;

    /** @var \SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy */
    private DefaultCombinationPolicy $policy;

    /** @var \SineMacula\Laravel\Mfa\Requirements\Requirement */
    private Requirement $requirement;

    /** @var list<\SineMacula\Laravel\Mfa\Proofs\Proof> */
    private array $proofs = [];

    /**
     * Build the policy, with nothing asked until a case is arranged.
     *
     * @return void
     */
    public function __construct()
    {
        $this->policy      = new DefaultCombinationPolicy;
        $this->requirement = Requirement::none();
    }

    /**
     * The cases, by name.
     *
     * @return iterable<string, array{case: string}>
     */
    public function provideCases(): iterable
    {
        foreach (array_keys(self::cases()) as $case) {
            yield $case => ['case' => $case];
        }
    }

    /**
     * Freeze the clock, build the case and prove its decision.
     *
     * @param  array{case: string}  $params
     * @return void
     *
     * @throws \LogicException
     */
    public function arrange(array $params): void
    {
        CarbonImmutable::setTestNow(SessionProofs::now());

        [$this->requirement, $this->proofs, $meets] = self::cases()[$params['case']];

        BenchOutcome::assert($params['case'], $this->policy->evaluate($this->requirement, ...$this->proofs)->meetsRequirement() === $meets);
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    public function releaseClock(): void
    {
        CarbonImmutable::setTestNow();
    }

    /**
     * Measure evaluating the case's proofs against its requirement.
     *
     * @return void
     */
    #[Iterations(3)]
    #[ParamProviders('provideCases')]
    #[Revs(100)]
    public function benchEvaluate(): void
    {
        $this->policy->evaluate($this->requirement, ...$this->proofs);
    }

    /**
     * Each case's requirement, its proofs and whether they meet it.
     *
     * @return array<string, array{\SineMacula\Laravel\Mfa\Requirements\Requirement, list<\SineMacula\Laravel\Mfa\Proofs\Proof>, bool}>
     */
    private static function cases(): array
    {
        $aal2 = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2);
        $aged = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, self::MAX_AGE);
        $full = $aal2->withAdditionalVerification()->withMultifactor()->withPhishingResistance();

        return [
            'first factor and one proof' => [$aal2, BenchProofs::firstFactorAndTotp(), true],
            'long session'               => [$aal2, BenchProofs::longSession(), true],
            'same channel refused'       => [Requirement::none()->withAdditionalVerification(), BenchProofs::sameChannel(), false],
            'empty requirement'          => [Requirement::none(), BenchProofs::firstFactor(), true],
            'full requirement'           => [$full, BenchProofs::firstFactorAndPasskey(), true],
            'within a maximum age'       => [$aged, BenchProofs::firstFactorAndTotp(self::MAX_AGE - 60), true],
            'beyond a maximum age'       => [$aged, BenchProofs::firstFactorAndTotp(self::MAX_AGE + 60), false],
        ];
    }
}
