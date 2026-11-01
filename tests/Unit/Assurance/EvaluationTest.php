<?php

declare(strict_types = 1);

namespace Tests\Unit\Assurance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;

/**
 * Unit tests for the `Evaluation` value: construction, validation of its `amr`
 * values and requirement parts, and serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Evaluation::class)]
final class EvaluationTest extends TestCase
{
    /**
     * An evaluation keeps each answer separately.
     *
     * @return void
     */
    public function testAnEvaluationKeepsEachAnswer(): void
    {
        $evaluation = new Evaluation(
            accepted: true,
            multifactor: false,
            level: AssuranceLevel::AAL1,
            phishingResistant: false,
            restricted: true,
            amr: ['sms', 'otp', 'mca'],
            met: [RequirementPart::ADDITIONAL_VERIFICATION],
            unmet: [RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL],
        );

        self::assertTrue($evaluation->accepted);
        self::assertFalse($evaluation->multifactor);
        self::assertSame(AssuranceLevel::AAL1, $evaluation->level);
        self::assertFalse($evaluation->phishingResistant);
        self::assertTrue($evaluation->restricted);
        self::assertSame(['sms', 'otp', 'mca'], $evaluation->amr);
        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $evaluation->met);
        self::assertSame([RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL], $evaluation->unmet);
        self::assertFalse($evaluation->meetsRequirement());
    }

    /**
     * An evaluation with no unmet part meets the requirement, including an
     * empty one.
     *
     * @return void
     */
    public function testAnEvaluationWithNothingUnmetMeetsTheRequirement(): void
    {
        $met = new Evaluation(true, true, AssuranceLevel::AAL2, true, false, ['pop', 'user', 'mfa'], [RequirementPart::MULTIFACTOR, RequirementPart::PHISHING_RESISTANCE], []);

        self::assertTrue($met->meetsRequirement());
        self::assertTrue((new Evaluation(false, false, AssuranceLevel::UNCLASSIFIED, false, false, [], [], []))->meetsRequirement());
    }

    /**
     * Evaluations whose `amr` values or parts are inconsistent.
     *
     * @return iterable<string, array{list<string>, list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>, list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>, string}>
     */
    public static function provideInvalidEvaluations(): iterable
    {
        yield 'a blank amr value' => [['otp', ' '], [], [], 'An amr value must not be blank.'];
        yield 'an empty amr value' => [[''], [], [], 'An amr value must not be blank.'];
        yield 'a repeated amr value' => [['otp', 'mfa', 'otp'], [], [], 'The amr value [otp] is listed more than once.'];
        yield 'a repeated met part' => [[], [RequirementPart::MULTIFACTOR, RequirementPart::MULTIFACTOR], [], 'The [multifactor] part is listed more than once.'];
        yield 'a repeated unmet part' => [
            [],
            [],
            [RequirementPart::MINIMUM_LEVEL, RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL],
            'The [minimum_level] part is listed more than once.',
        ];
        yield 'a part both met and unmet' => [
            [],
            [RequirementPart::PHISHING_RESISTANCE],
            [RequirementPart::PHISHING_RESISTANCE],
            'The [phishing_resistance] part cannot be both met and unmet.',
        ];
    }

    /**
     * An evaluation that repeats an `amr` value or a part, or both meets and
     * misses a part, is refused.
     *
     * @param  list<string>  $amr
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $met
     * @param  list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>  $unmet
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideInvalidEvaluations')]
    public function testAnInconsistentEvaluationIsRefused(array $amr, array $met, array $unmet, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new Evaluation(true, false, AssuranceLevel::AAL1, false, false, $amr, $met, $unmet);
    }

    /**
     * The serialised form uses snake_case keys and the values of the level and
     * the parts.
     *
     * @return void
     */
    public function testTheSerializedForm(): void
    {
        $met        = [RequirementPart::ADDITIONAL_VERIFICATION, RequirementPart::MULTIFACTOR];
        $evaluation = new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['otp', 'mfa'], $met, [RequirementPart::PHISHING_RESISTANCE]);

        $expected = [
            'accepted'           => true,
            'multifactor'        => true,
            'level'              => 'aal2',
            'phishing_resistant' => false,
            'restricted'         => false,
            'amr'                => ['otp', 'mfa'],
            'met'                => ['additional_verification', 'multifactor'],
            'unmet'              => ['phishing_resistance'],
        ];

        self::assertSame($expected, $evaluation->toArray());
        self::assertSame($expected, $evaluation->jsonSerialize());
        self::assertSame(
            '{"accepted":false,"multifactor":false,"level":"unclassified","phishing_resistant":false,"restricted":true,"amr":[],"met":[],"unmet":["multifactor"]}',
            json_encode(new Evaluation(false, false, AssuranceLevel::UNCLASSIFIED, false, true, [], [], [RequirementPart::MULTIFACTOR])),
        );
    }
}
