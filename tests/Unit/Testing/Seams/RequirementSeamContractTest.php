<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Seams\DriftingSeams;
use Tests\Fixtures\Seams\FaultySeams;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementSeamContract::class)]
final class RequirementSeamContractTest extends TestCase
{
    /**
     * @return void
     */
    public function testRejectsARequirementThatKeepsState(): void
    {
        $faulty   = new FaultySeams;
        $identity = new NonEloquentIdentity;

        $this->expectException(AssertionFailedError::class);

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(
            static fn () => $faulty->requirementFor($identity, 'web'),
            static fn () => $faulty->requirementFor($identity, 'api'),
        );
    }

    /**
     * The same answer to a question asked twice in a row, but a different one
     * once another was asked in between.
     *
     * @return void
     */
    public function testRejectsARequirementThatRemembersTheQuestionBefore(): void
    {
        $drifting = new DriftingSeams;
        $identity = new NonEloquentIdentity;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('whatever was asked in between');

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(
            static fn () => $drifting->requirementFor($identity, 'web'),
            static fn () => $drifting->requirementFor($identity, 'api'),
        );
    }

    /**
     * As one that keeps its first answer for everyone does.
     *
     * @return void
     */
    public function testRejectsARequirementThatAnswersAnotherQuestionAsTheOneBefore(): void
    {
        $answer = Requirement::none()->withMultifactor();

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not answer another question as it answered the one before');

        RequirementSeamContract::assertAnswersAnotherQuestionItsOwnWay(static fn () => $answer, static fn () => $answer);
    }

    /**
     * @return void
     */
    public function testAcceptsARequirementThatAnswersAnotherQuestionItsOwnWay(): void
    {
        RequirementSeamContract::assertAnswersAnotherQuestionItsOwnWay(
            static fn () => Requirement::none()->withMultifactor(),
            static fn () => Requirement::none(),
        );
    }
}
