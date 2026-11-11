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
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * When the freshest multifactor evidence was made: never a weaker proof's time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultCombinationPolicy::class)]
#[CoversClass(Combination::class)]
#[CoversClass(Evaluation::class)]
final class MultifactorAtEvaluationTest extends TestCase
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
     * @return void
     */
    public function testAProofCompletingTheCombinationIsItsEvidence(): void
    {
        $proofs = new SignInProofs;

        self::assertMultifactorAt(100, $this->evaluate($proofs->password(1000), $proofs->totp(100))->multifactorAt);
    }

    /**
     * However fresh the weaker proof after it.
     *
     * @return void
     */
    public function testAFirstFactorMultifactorAloneKeepsItsTime(): void
    {
        $proofs = new SignInProofs;

        self::assertMultifactorAt(1000, $this->evaluate($proofs->passkey(true, 1000), $proofs->email(10))->multifactorAt);
    }

    /**
     * After a first factor that is too.
     *
     * @return void
     */
    public function testAFurtherProofMultifactorAloneIsFreshEvidence(): void
    {
        $proofs = new SignInProofs;

        self::assertMultifactorAt(10, $this->evaluate($proofs->passkey(true, 1000), $proofs->passkeyFactor(true, 10))->multifactorAt);
    }

    /**
     * @return void
     */
    public function testTheLatestEvidenceWinsAndAWeakerProofDisplacesNone(): void
    {
        $proofs = new SignInProofs;

        self::assertMultifactorAt(100, $this->evaluate($proofs->password(1000), $proofs->totp(500), $proofs->totp(100))->multifactorAt);
        self::assertMultifactorAt(800, $this->evaluate($proofs->password(1000), $proofs->totp(800), $proofs->email(10))->multifactorAt);
    }

    /**
     * @return void
     */
    public function testNoMultifactorHasNoEvidence(): void
    {
        $proofs     = new SignInProofs;
        $evaluation = $this->evaluate($proofs->password(1000), $proofs->email(10));

        self::assertFalse($evaluation->multifactor);
        self::assertNull($evaluation->multifactorAt);
    }

    /**
     * @return void
     */
    public function testTheEvidenceTimeIsNotSerialised(): void
    {
        $proofs     = new SignInProofs;
        $evaluation = $this->evaluate($proofs->password(1000), $proofs->totp(100));

        self::assertArrayNotHasKey('multifactor_at', $evaluation->toArray());
        self::assertArrayNotHasKey('multifactor_at', $evaluation->jsonSerialize());
    }

    /**
     * One that is may leave it unsaid.
     *
     * @return void
     */
    public function testOnlyAMultifactorEvaluationSaysWhen(): void
    {
        self::assertNull(self::evaluation(true, null)->multifactorAt);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An evaluation that is not multifactor cannot say when its multifactor evidence was made.');

        self::evaluation(false, CarbonImmutable::now());
    }

    /**
     * Nothing for an answer it does not give.
     *
     * @return void
     */
    public function testACombinationSaysWhenItsEvidenceWasMade(): void
    {
        $proofs      = new SignInProofs;
        $multifactor = static fn (Combination $combination): bool => $combination->isMultifactor();

        self::assertMultifactorAt(100, Combination::after($proofs->password(1000), $proofs->totp(100))->evidencedAt($multifactor));
        self::assertMultifactorAt(1000, Combination::after($proofs->passkey(true, 1000), $proofs->email(10))->evidencedAt($multifactor));
        self::assertNull(Combination::after($proofs->password(1000), $proofs->email(10))->evidencedAt($multifactor));
    }

    /**
     * Against no requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    private function evaluate(Proof ...$proofs): Evaluation
    {
        return (new DefaultCombinationPolicy)->evaluate(Requirement::none(), ...$proofs);
    }

    /**
     * @param  bool  $multifactor
     * @param  ?\Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    private static function evaluation(bool $multifactor, ?CarbonImmutable $at): Evaluation
    {
        return new Evaluation(
            accepted         : true,
            multifactor      : $multifactor,
            level            : AssuranceLevel::AAL2,
            phishingResistant: false,
            restricted       : false,
            amr              : $multifactor ? ['mfa'] : [],
            met              : [],
            unmet            : [],
            multifactorAt    : $at,
        );
    }

    /**
     * @param  int  $seconds
     * @return \Carbon\CarbonImmutable
     */
    private static function ago(int $seconds): CarbonImmutable
    {
        return CarbonImmutable::parse(self::NOW)->subSeconds($seconds);
    }

    /**
     * @param  int  $seconds
     * @param  ?\Carbon\CarbonImmutable  $at
     * @return void
     */
    private static function assertMultifactorAt(int $seconds, ?CarbonImmutable $at): void
    {
        self::assertNotNull($at);
        self::assertTrue(self::ago($seconds)->equalTo($at));
    }
}
