<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Illuminate\Database\Eloquent\Collection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `FactorChangeRequest`: a request that contradicts itself is refused
 * when it is built, and a request takes a collection of the shipped factor
 * model as it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChangeRequest::class)]
final class FactorChangeRequestTest extends TestCase
{
    /**
     * Rows of a request that contradicts itself.
     *
     * @return iterable<string, array{string, \SineMacula\Laravel\Mfa\Enums\FactorChange, ?string, string}>
     */
    public static function contradictoryRequests(): iterable
    {
        yield 'a blank sign-in' => [' ', FactorChange::ADD_FACTOR, null, 'A factor change is made from a sign-in, so its session id must not be blank.'];
        yield 'a removal naming no factor' => [SignInProofs::SESSION, FactorChange::REMOVE_FACTOR, null, 'The change [mfa.remove_factor] needs a factor.'];
        yield 'a grant naming a factor' => [SignInProofs::SESSION, FactorChange::ADD_FACTOR, 'factor-1', 'The change [mfa.add_factor] names no factor.'];
    }

    /**
     * A request that contradicts itself is refused when it is built.
     *
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  ?string  $factorId
     * @param  string  $message
     * @return void
     */
    #[DataProvider('contradictoryRequests')]
    public function testARequestThatContradictsItselfIsRefused(string $session, FactorChange $change, ?string $factorId, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new FactorChangeRequest($this->person(), SignInProofs::APPLICATION, $session, $change, new Collection, $factorId);
    }

    /**
     * A request takes a collection of the shipped factor model as it is, and
     * carries it unchanged.
     *
     * @return void
     */
    public function testARequestTakesTheShippedFactorModelsCollection(): void
    {
        $factors = new Collection([new Factor]);

        $request = new FactorChangeRequest($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, FactorChange::ADD_FACTOR, $factors);

        self::assertSame($factors, $request->factors);
    }

    /**
     * A person.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'change-request@example.test']);
    }
}
