<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Support\FactorStateLocks;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorStateLocks::class)]
final class FactorStateLocksTest extends TestCase
{
    /**
     * @return void
     */
    public function testHoldsAnOwnerOnlyWhileItsCallbackRuns(): void
    {
        $locks = new FactorStateLocks;
        $owner = new ProofOwner('user', '7');

        $held = $locks->hold($owner, static fn (): array => [$locks->holds($owner), $locks->holds(new ProofOwner('user', '8'))]);

        self::assertSame([true, false], $held);
        self::assertFalse($locks->holds($owner));
    }

    /**
     * @return void
     */
    public function testANestedHoldOfTheSameOwnerLeavesTheOuterOneHolding(): void
    {
        $locks = new FactorStateLocks;
        $owner = new ProofOwner('user', '7');

        self::assertTrue($locks->hold($owner, static function () use ($locks, $owner): bool {
            $locks->hold($owner, static fn (): null => null);

            return $locks->holds($owner);
        }));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedCallbackStopsHolding(): void
    {
        $locks = new FactorStateLocks;
        $owner = new ProofOwner('user', '7');

        try {
            $locks->hold($owner, static function (): never {
                throw new \RuntimeException('The change failed.');
            });
        } catch (\RuntimeException $failure) {
            self::assertSame('The change failed.', $failure->getMessage());
        }

        self::assertFalse($locks->holds($owner));
    }
}
