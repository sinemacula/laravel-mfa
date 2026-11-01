<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Unit tests for the `Requirement` value: what each part asks, validation,
 * composition by `strictest()` and serialisation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Requirement::class)]
final class RequirementTest extends TestCase
{
    /**
     * The empty requirement asks for nothing.
     *
     * @return void
     */
    public function testTheEmptyRequirementAsksForNothing(): void
    {
        $requirement = Requirement::none();

        self::assertTrue($requirement->isEmpty());
        self::assertSame([], $requirement->parts());
        self::assertNull($requirement->minimumLevel);

        foreach (RequirementPart::cases() as $part) {
            self::assertFalse($requirement->asks($part));
            self::assertNull($requirement->maxAge($part));
        }
    }

    /**
     * Each part is asked for with its own maximum age, and the others are left
     * as they were.
     *
     * @return void
     */
    public function testEachPartIsAskedWithItsOwnMaximumAge(): void
    {
        $requirement = Requirement::none()
            ->withPhishingResistance()
            ->withMinimumLevel(AssuranceLevel::AAL2, 600)
            ->withMultifactor(300)
            ->withAdditionalVerification(900);

        self::assertFalse($requirement->isEmpty());
        self::assertSame(RequirementPart::cases(), $requirement->parts());
        self::assertSame(AssuranceLevel::AAL2, $requirement->minimumLevel);
        self::assertSame(900, $requirement->maxAge(RequirementPart::ADDITIONAL_VERIFICATION));
        self::assertSame(300, $requirement->maxAge(RequirementPart::MULTIFACTOR));
        self::assertSame(600, $requirement->maxAge(RequirementPart::MINIMUM_LEVEL));
        self::assertNull($requirement->maxAge(RequirementPart::PHISHING_RESISTANCE));
        self::assertTrue($requirement->asks(RequirementPart::PHISHING_RESISTANCE));
    }

    /**
     * Asking for a part leaves the requirement it was asked of unchanged.
     *
     * @return void
     */
    public function testARequirementIsImmutable(): void
    {
        $none        = Requirement::none();
        $multifactor = $none->withMultifactor();
        $level       = $multifactor->withMinimumLevel(AssuranceLevel::AAL1);

        self::assertTrue($none->isEmpty());
        self::assertSame([RequirementPart::MULTIFACTOR], $multifactor->parts());
        self::assertNull($multifactor->minimumLevel);
        self::assertSame([RequirementPart::MULTIFACTOR, RequirementPart::MINIMUM_LEVEL], $level->parts());
    }

    /**
     * Asking for a part again replaces what it asked.
     *
     * @return void
     */
    public function testAskingForAPartAgainReplacesIt(): void
    {
        $requirement = Requirement::none()
            ->withMultifactor(300)
            ->withMultifactor()
            ->withMinimumLevel(AssuranceLevel::AAL2, 60)
            ->withMinimumLevel(AssuranceLevel::AAL1);

        self::assertNull($requirement->maxAge(RequirementPart::MULTIFACTOR));
        self::assertSame(AssuranceLevel::AAL1, $requirement->minimumLevel);
        self::assertNull($requirement->maxAge(RequirementPart::MINIMUM_LEVEL));
    }

    /**
     * Maximum ages below one second.
     *
     * @return iterable<string, array{int}>
     */
    public static function provideAgesBelowOneSecond(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    /**
     * A maximum age is at least one second, whichever part it is for.
     *
     * @param  int  $maxAge
     * @return void
     */
    #[DataProvider('provideAgesBelowOneSecond')]
    public function testAMaximumAgeBelowOneSecondIsRefused(int $maxAge): void
    {
        $asks = [
            static fn (): Requirement => Requirement::none()->withAdditionalVerification($maxAge),
            static fn (): Requirement => Requirement::none()->withMultifactor($maxAge),
            static fn (): Requirement => Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, $maxAge),
            static fn (): Requirement => Requirement::none()->withPhishingResistance($maxAge),
        ];

        foreach ($asks as $ask) {
            try {
                $ask();
                self::fail('A maximum age below one second was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The maximum age of a requirement part must be at least one second.', $exception->getMessage());
            }
        }
    }

    /**
     * A maximum age of one second is the shortest allowed.
     *
     * @return void
     */
    public function testAMaximumAgeOfOneSecondIsAccepted(): void
    {
        self::assertSame(1, Requirement::none()->withMultifactor(1)->maxAge(RequirementPart::MULTIFACTOR));
    }

    /**
     * Unclassified is no level to ask for.
     *
     * @return void
     */
    public function testTheUnclassifiedLevelIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A requirement cannot ask for the [unclassified] level.');

        Requirement::none()->withMinimumLevel(AssuranceLevel::UNCLASSIFIED);
    }

    /**
     * Compositions and the strictest requirement each gives.
     *
     * @return iterable<string, array{list<\SineMacula\Laravel\Mfa\Requirements\Requirement>, \SineMacula\Laravel\Mfa\Requirements\Requirement}>
     */
    public static function provideCompositions(): iterable
    {
        $none = Requirement::none();

        yield 'nothing' => [[], $none];
        yield 'one requirement' => [[$none->withMultifactor(60)], $none->withMultifactor(60)];
        yield 'empty parts' => [[$none, $none], $none];
        yield 'a part asked by either' => [[$none->withMultifactor(), $none->withPhishingResistance()], $none->withMultifactor()->withPhishingResistance()];
        yield 'the shorter maximum age' => [[$none->withMultifactor(900), $none->withMultifactor(300)], $none->withMultifactor(300)];
        yield 'the shorter maximum age, given last' => [[$none->withMultifactor(300), $none->withMultifactor(900)], $none->withMultifactor(300)];
        yield 'a maximum age over none' => [[$none->withAdditionalVerification(), $none->withAdditionalVerification(120)], $none->withAdditionalVerification(120)];
        yield 'a maximum age over none, given first' => [[$none->withAdditionalVerification(120), $none->withAdditionalVerification()], $none->withAdditionalVerification(120)];
        yield 'the higher level' => [[$none->withMinimumLevel(AssuranceLevel::AAL1), $none->withMinimumLevel(AssuranceLevel::AAL2)], $none->withMinimumLevel(AssuranceLevel::AAL2)];
        yield 'the higher level, given first' => [
            [$none->withMinimumLevel(AssuranceLevel::AAL3), $none->withMinimumLevel(AssuranceLevel::AAL2)],
            $none->withMinimumLevel(AssuranceLevel::AAL3),
        ];
        yield 'the higher level with the shorter age' => [
            [$none->withMinimumLevel(AssuranceLevel::AAL1, 60), $none->withMinimumLevel(AssuranceLevel::AAL2, 600)],
            $none->withMinimumLevel(AssuranceLevel::AAL2, 60),
        ];
        yield 'a level over none' => [[$none->withMultifactor(), $none->withMinimumLevel(AssuranceLevel::AAL1)], $none->withMultifactor()->withMinimumLevel(AssuranceLevel::AAL1)];
        yield 'five sources' => [
            [
                $none->withAdditionalVerification(),
                $none,
                $none->withMultifactor(3600),
                $none->withMinimumLevel(AssuranceLevel::AAL2),
                $none->withMultifactor(900)->withPhishingResistance(300),
            ],
            $none->withAdditionalVerification()->withMultifactor(900)->withMinimumLevel(AssuranceLevel::AAL2)->withPhishingResistance(300),
        ];
    }

    /**
     * The strictest of several requirements asks every part any of them asks,
     * the highest level, and each part's shortest maximum age.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Requirements\Requirement>  $parts
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $expected
     * @return void
     */
    #[DataProvider('provideCompositions')]
    public function testTheStrictestRequirement(array $parts, Requirement $expected): void
    {
        $strictest = Requirement::strictest(...$parts);

        self::assertSame($expected->toArray(), $strictest->toArray());
        self::assertSame($expected->toArray(), Requirement::strictest(...array_reverse($parts))->toArray());
    }

    /**
     * The serialised form names each part asked for, in a fixed order, with its
     * maximum age and, for a level, the level.
     *
     * @return void
     */
    public function testTheSerializedForm(): void
    {
        $requirement = Requirement::none()
            ->withPhishingResistance()
            ->withMinimumLevel(AssuranceLevel::AAL2, 600)
            ->withAdditionalVerification(900);

        $expected = [
            'additional_verification' => ['max_age' => 900],
            'minimum_level'           => ['level' => 'aal2', 'max_age' => 600],
            'phishing_resistance'     => ['max_age' => null],
        ];

        self::assertSame($expected, $requirement->toArray());
        self::assertSame($expected, $requirement->jsonSerialize());
        self::assertSame([], Requirement::none()->toArray());
    }

    /**
     * A requirement read back from its serialised form, or from its JSON,
     * equals the original, and a part without a maximum age may leave it out.
     *
     * @return void
     */
    public function testARequirementRoundTrips(): void
    {
        $requirement = Requirement::none()->withAdditionalVerification()->withMultifactor(300)->withMinimumLevel(AssuranceLevel::AAL3, 60)->withPhishingResistance(30);

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) json_encode($requirement), true);

        self::assertEquals($requirement, Requirement::fromArray($requirement->toArray()));
        self::assertEquals($requirement, Requirement::fromArray($decoded));
        self::assertEquals(Requirement::none(), Requirement::fromArray([]));
        self::assertEquals(Requirement::none()->withMultifactor(), Requirement::fromArray(['multifactor' => []]));
    }

    /**
     * Serialised forms that are not a requirement.
     *
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideMalformedRequirements(): iterable
    {
        yield 'an unknown part' => [['mfa' => []], 'The [mfa] part of a serialised requirement is not a known part.'];
        yield 'a part that is not an array' => [['multifactor' => true], 'The [multifactor] field of a serialised requirement must be an array.'];
        yield 'a maximum age that is not an integer' => [
            ['multifactor' => ['max_age' => '300']],
            'The [max_age] field of the [multifactor] part of a serialised requirement must be an integer or null.',
        ];
        yield 'a level part without a level' => [['minimum_level' => []], 'The [level] field of the [minimum_level] part of a serialised requirement must be a string.'];
        yield 'an unknown level' => [['minimum_level' => ['level' => 'aal4']], 'The [level] field of the [minimum_level] part of a serialised requirement is not a known value.'];
        yield 'the unclassified level' => [['minimum_level' => ['level' => 'unclassified']], 'A requirement cannot ask for the [unclassified] level.'];
        yield 'a maximum age of zero' => [['phishing_resistance' => ['max_age' => 0]], 'The maximum age of a requirement part must be at least one second.'];
    }

    /**
     * A serialised form that is not a requirement is refused, so a mistyped
     * part never weakens it.
     *
     * @param  array<string, mixed>  $data
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedRequirements')]
    public function testAMalformedRequirementIsRefused(array $data, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        Requirement::fromArray($data);
    }
}
