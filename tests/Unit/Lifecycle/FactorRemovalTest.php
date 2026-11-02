<?php

declare(strict_types = 1);

namespace Tests\Unit\Lifecycle;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Passkeys\Concerns\ArrangesPasskeys;
use Tests\TestCase;

/**
 * Tests for `FactorRemoval`, the removal every entry point shares: it runs only
 * inside the identity's factor state transaction, and removes a factor by its
 * id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRemoval::class)]
final class FactorRemovalTest extends TestCase
{
    use ArrangesPasskeys;

    /**
     * A removal outside a transaction is refused, and removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalOutsideATransactionIsRefused(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user);

        try {
            $this->removal()->remove($user, self::APPLICATION, $factor, new Collection([$factor]));
            self::fail('A removal outside a transaction was expected to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A factor is removed only inside the identity\'s factor state transaction.', $exception->getMessage());
        }

        self::assertTrue(Factor::query()->whereKey($factor->id)->exists());
    }

    /**
     * A factor with no id is not removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorWithNoIdIsRefused(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->confirmedFactor($user)->replicate();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('A factor is removed by its id.');

        DB::transaction(fn () => $this->removal()->remove($user, self::APPLICATION, $factor, new Collection([$factor])));
    }

    /**
     * The removal under test.
     *
     * @return \SineMacula\Laravel\Mfa\Lifecycle\FactorRemoval
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function removal(): FactorRemoval
    {
        return $this->container()->make(FactorRemoval::class);
    }
}
