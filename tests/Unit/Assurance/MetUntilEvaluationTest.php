<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Combination;
use SineMacula\Laravel\Mfa\Assurance\DefaultCombinationPolicy;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * The earliest time a part bounded by a maximum age stops being met, judged on
 * the evidence each part rests on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultCombinationPolicy::class)]
#[CoversClass(Combination::class)]
#[CoversClass(Evaluation::class)]
final class MetUntilEvaluationTest extends TestCase
{
    /** @var string The time the clock is frozen at. */
    private const string NOW = '2026-11-01 12:00:00';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(self::NOW);
    }

    /**
     * Its evidence's time plus its maximum age.
     *
     * @return void
     */
    public function testAPartIsMetUntilItsEvidenceIsTooOld(): void
    {
        $proofs = new SignInProofs;

        $evaluation = $this->evaluate(Requirement::none()->withAdditionalVerification(900), $proofs->password(1000), $proofs->totp(800));

        self::assertMetUntil(100, $evaluation->metUntil);
    }

    /**
     * @return void
     */
    public function testSeveralPartsTakeTheEarliest(): void
    {
        $proofs      = new SignInProofs;
        $requirement = Requirement::none()->withAdditionalVerification(300)->withMultifactor(900);

        self::assertMetUntil(200, $this->evaluate($requirement, $proofs->password(1000), $proofs->totp(100))->metUntil);

        $requirement = Requirement::none()->withMultifactor(900)->withAdditionalVerification(300);

        self::assertMetUntil(200, $this->evaluate($requirement, $proofs->password(1000), $proofs->totp(100))->metUntil);
    }

    /**
     * Among the combinations providing it.
     *
     * @return void
     */
    public function testAPartTakesItsLatestEvidence(): void
    {
        $proofs      = new SignInProofs;
        $requirement = Requirement::none()->withAdditionalVerification(900);

        self::assertMetUntil(800, $this->evaluate($requirement, $proofs->password(1000), $proofs->totp(500), $proofs->totp(100))->metUntil);
        self::assertMetUntil(800, $this->evaluate($requirement, $proofs->password(1000), $proofs->totp(100), $proofs->totp(500))->metUntil);
    }

    /**
     * A level the first factor gives alone is as old as it, and an additional
     * factor does not refresh it.
     *
     * @return void
     */
    public function testEvidenceOnTheFirstFactorUsesItsTime(): void
    {
        $proofs      = new SignInProofs;
        $requirement = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, 600);

        $until = $this->evaluate($requirement, $proofs->password(500), $proofs->email(10))->metUntil;

        self::assertMetUntil(100, $until);
    }

    /**
     * One bounded part still sets it among unbounded ones.
     *
     * @return void
     */
    public function testAnUnboundedPartSetsNoTime(): void
    {
        $proofs = new SignInProofs;

        self::assertNull($this->evaluate(Requirement::none()->withAdditionalVerification(), $proofs->password(100), $proofs->totp(50))->metUntil);
        self::assertMetUntil(250, $this->evaluate(
            Requirement::none()->withAdditionalVerification()->withMultifactor(300),
            $proofs->password(100),
            $proofs->totp(50),
        )->metUntil);
    }

    /**
     * One built with an unmet part and a time is refused.
     *
     * @return void
     */
    public function testAnUnmetPartHasNoTime(): void
    {
        $proofs = new SignInProofs;

        self::assertNull($this->evaluate(Requirement::none()->withAdditionalVerification(900), $proofs->password(10))->metUntil);

        new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['mfa'], [RequirementPart::MULTIFACTOR], [], CarbonImmutable::now());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An evaluation with an unmet part cannot say when it stops meeting the requirement.');

        new Evaluation(false, false, AssuranceLevel::UNCLASSIFIED, false, false, [], [], [RequirementPart::MULTIFACTOR], CarbonImmutable::now());
    }

    /**
     * It is an answer about now.
     *
     * @return void
     */
    public function testTheTimeIsNotInTheArrayOrJson(): void
    {
        $proofs     = new SignInProofs;
        $evaluation = $this->evaluate(Requirement::none()->withAdditionalVerification(900), $proofs->password(10), $proofs->totp(5));

        self::assertNotNull($evaluation->metUntil);
        self::assertArrayNotHasKey('met_until', $evaluation->toArray());
        self::assertSame($evaluation->toArray(), $evaluation->jsonSerialize());
    }

    /**
     * @return void
     */
    public function testACombinationWithoutTheAnswerHoldsItUntilNoTime(): void
    {
        $combination = Combination::alone((new SignInProofs)->password(10));

        self::assertNull($combination->heldUntil(static fn (Combination $candidate): bool => $candidate->accepted, 60));
        self::assertMetUntil(50, $combination->heldUntil(static fn (Combination $candidate): bool => !$candidate->accepted, 60));
    }

    /**
     * @param  int  $seconds
     * @return \Carbon\CarbonImmutable
     */
    private static function after(int $seconds): CarbonImmutable
    {
        return CarbonImmutable::parse(self::NOW)->addSeconds($seconds);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    private function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        return (new DefaultCombinationPolicy)->evaluate($requirement, ...$proofs);
    }

    /**
     * @param  int  $seconds
     * @param  ?\Carbon\CarbonImmutable  $until
     * @return void
     */
    private static function assertMetUntil(int $seconds, ?CarbonImmutable $until): void
    {
        self::assertNotNull($until);
        self::assertTrue(self::after($seconds)->equalTo($until));
    }
}
