<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\OperationRequirements;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Tests for `OperationRequirements`: the requirement an operation's step-up
 * must meet is the stricter of the application's configured one and the
 * caller's, either alone when the other is absent, and none with neither or for
 * a name that is not an operation's. A caller's requirement that asks for
 * nothing adds nothing; one without a bounded age on every part is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationRequirements::class)]
final class OperationRequirementsTest extends TestCase
{
    /** @var string The application the tests configure. */
    private const string APPLICATION = 'web';

    /**
     * Rows of an operation, the caller's requirement, and the effective
     * requirement, serialised, or `null` for none.
     *
     * @return iterable<string, array{string, ?\SineMacula\Laravel\Mfa\Requirements\Requirement, ?array<string, array<string, int|string|null>>}>
     */
    public static function operations(): iterable
    {
        $caller = Requirement::none()->withAdditionalVerification(600)->withMinimumLevel(AssuranceLevel::AAL2, 60);

        yield 'a package operation, alone' => ['mfa.add_factor', null, ['additional_verification' => ['max_age' => 900]]];
        yield 'a package operation, with an empty caller requirement' => ['mfa.add_factor', Requirement::none(), ['additional_verification' => ['max_age' => 900]]];
        yield 'a package operation, with a caller requirement' => [
            'mfa.add_factor',
            $caller,
            ['additional_verification' => ['max_age' => 600], 'minimum_level' => ['level' => 'aal2', 'max_age' => 60]],
        ];
        yield 'an operation the application configures, with a looser caller requirement' => [
            'mfa.remove_factor',
            Requirement::none()->withAdditionalVerification(3600),
            ['additional_verification' => ['max_age' => 120]],
        ];
        yield 'an operation configured with a requirement of its own' => [
            'billing.change_plan',
            null,
            ['minimum_level' => ['level' => 'aal1', 'max_age' => 30]],
        ];
        yield 'an operation nobody configures, with a caller requirement' => [
            'reports.export',
            $caller,
            ['additional_verification' => ['max_age' => 600], 'minimum_level' => ['level' => 'aal2', 'max_age' => 60]],
        ];
        yield 'an operation nobody configures, alone' => ['reports.export', null, null];
        yield 'an operation nobody configures, with an empty caller requirement' => ['reports.export', Requirement::none(), null];
        yield 'a name in capitals, with a caller requirement' => ['Reports.Export', $caller, null];
        yield 'a name with a trailing newline, with a caller requirement' => ["reports.export\n", $caller, null];
        yield 'a blank name, with a caller requirement' => ['', $caller, null];
    }

    /**
     * The effective requirement is the strictest of whichever of the configured
     * and the caller's requirements exist.
     *
     * @param  string  $operation
     * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $caller
     * @param  ?array<string, array<string, int|string|null>>  $expected
     * @return void
     */
    #[DataProvider('operations')]
    public function testTheEffectiveRequirementIsTheStrictestOfWhatExists(string $operation, ?Requirement $caller, ?array $expected): void
    {
        self::assertSame($expected, self::requirements()->effective(self::APPLICATION, $operation, $caller)?->toArray());
    }

    /**
     * Rows of a caller's requirement that is not bounded, and the part named.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Requirements\Requirement, string}>
     */
    public static function unboundedCallers(): iterable
    {
        yield 'a part with no maximum age' => [Requirement::none()->withAdditionalVerification(60)->withMultifactor(), 'multifactor'];
        yield 'a part older than a day' => [Requirement::none()->withPhishingResistance(86401), 'phishing_resistance'];
    }

    /**
     * A caller's requirement with a part that carries no maximum age, or one
     * longer than a day, is refused, for a name that is not an operation's
     * too.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $caller
     * @param  string  $part
     * @return void
     */
    #[DataProvider('unboundedCallers')]
    public function testAnUnboundedCallerRequirementIsRefused(Requirement $caller, string $part): void
    {
        foreach (['mfa.add_factor', 'Not An Operation'] as $operation) {

            try {
                self::requirements()->effective(self::APPLICATION, $operation, $caller);
                self::fail('Expected the caller\'s requirement to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('A caller\'s requirement must give every part a max_age from 1 to 86400 seconds, which its [%s] part does not.', $part), $exception->getMessage());
            }
        }
    }

    /**
     * A caller's requirement of exactly a day is bounded.
     *
     * @return void
     */
    public function testACallerRequirementOfADayIsBounded(): void
    {
        $caller = Requirement::none()->withMultifactor(86400);

        self::assertSame(
            ['additional_verification' => ['max_age' => 900], 'multifactor' => ['max_age' => 86400]],
            self::requirements()->effective(self::APPLICATION, 'mfa.add_factor', $caller)?->toArray(),
        );
    }

    /**
     * The requirements of the application the tests configure.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\OperationRequirements
     */
    private static function requirements(): OperationRequirements
    {
        return new OperationRequirements(new Repository(['mfa' => ['applications' => [self::APPLICATION => ['freshness' => [
            'mfa.remove_factor'   => 120,
            'billing.change_plan' => ['minimum_level' => ['level' => 'aal1', 'max_age' => 30]],
        ]]]]]));
    }
}
