<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Requirements\FreshnessBounds;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessBounds::class)]
final class FreshnessBoundsTest extends TestCase
{
    /**
     * The empty requirement included.
     *
     * @return void
     */
    public function testABoundedRequirementIsReturned(): void
    {
        $bounded = Requirement::none()->withAdditionalVerification(1)->withMinimumLevel(AssuranceLevel::AAL2, 86400);

        self::assertSame($bounded, FreshnessBounds::assertBounded($bounded, 'The requirement'));
        self::assertTrue(FreshnessBounds::assertBounded(Requirement::none(), 'The requirement')->isEmpty());
        self::assertSame(86400, FreshnessBounds::MOST_SECONDS);
    }

    /**
     * No maximum age, or one longer than a day; the error names the subject.
     *
     * @return void
     */
    public function testAnUnboundedPartIsRefused(): void
    {
        $unbounded = [
            'multifactor'   => Requirement::none()->withAdditionalVerification(60)->withMultifactor(),
            'minimum_level' => Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, 86401),
        ];

        foreach ($unbounded as $part => $requirement) {

            try {
                FreshnessBounds::assertBounded($requirement, 'The setting');
                self::fail('Expected the requirement to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('The setting must give every part a max_age from 1 to 86400 seconds, which its [%s] part does not.', $part), $exception->getMessage());
            }
        }
    }
}
