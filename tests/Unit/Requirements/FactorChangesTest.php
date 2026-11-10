<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\FactorChangeGate;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Enums\FactorChange;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Requirements\FactorChangeRequest;
use SineMacula\Laravel\Mfa\Requirements\FactorChanges;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\RefusingFreshnessGate;
use Tests\Fixtures\Requirements\ScriptedFactorChangeGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `FactorChanges`, `FactorChangeRequest` and `FactorChange`: the
 * bound gate is asked only inside a transaction, with the request each flow
 * builds and the requirement the application configures; a grant without an end
 * in the future is refused; and a bound gate's refusal is the package's, while
 * one a seam throws through the default stays the seam's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorChanges::class)]
#[CoversClass(FactorChangeRequest::class)]
#[CoversClass(FactorChange::class)]
final class FactorChangesTest extends TestCase
{
    /**
     * The gate is never asked outside a transaction.
     *
     * @return void
     */
    public function testTheGateIsNeverAskedOutsideATransaction(): void
    {
        $gate = $this->bind(new ScriptedFactorChangeGate);

        try {
            $this->changes()->allow($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, FactorChange::GENERATE_RECOVERY_CODES, new Collection);
            self::fail('Asking outside a transaction was expected to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('A factor change is authorised only inside the identity\'s factor state transaction.', $exception->getMessage());
        }

        self::assertSame([], $gate->requests);
    }

    /**
     * The request carries the identity, the application, the sign-in, the
     * change, the factors and the factor a removal names, and the requirement
     * the application configures for the change's operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRequestCarriesTheChangeAndTheConfiguredRequirement(): void
    {
        config()->set('mfa.applications.' . SignInProofs::APPLICATION . '.freshness', ['mfa.remove_factor' => 120]);

        $gate    = $this->bind(new ScriptedFactorChangeGate);
        $user    = $this->person();
        $factors = new Collection;

        DB::transaction(fn () => $this->changes()->allow($user, SignInProofs::APPLICATION, SignInProofs::SESSION, FactorChange::REMOVE_FACTOR, $factors, 'factor-1'));

        $request = $gate->requests[0];

        self::assertSame($user, $request->identity);
        self::assertSame(SignInProofs::APPLICATION, $request->application);
        self::assertSame(SignInProofs::SESSION, $request->session);
        self::assertSame(FactorChange::REMOVE_FACTOR, $request->change);
        self::assertSame($factors, $request->factors);
        self::assertSame('factor-1', $request->factorId);
        self::assertSame(120, $request->requirement?->maxAge(RequirementPart::ADDITIONAL_VERIFICATION));
    }

    /**
     * A first additional factor carries no configured requirement, whatever the
     * application configures under its name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstAdditionalFactorCarriesNoRequirement(): void
    {
        config()->set('mfa.applications.' . SignInProofs::APPLICATION . '.freshness', ['mfa.add_first_additional_factor' => 120]);

        $gate = $this->bind(new ScriptedFactorChangeGate(CarbonImmutable::now()->addMinute()));

        $this->granted(FactorChange::ADD_FIRST_ADDITIONAL_FACTOR);

        self::assertNull($gate->requests[0]->requirement);
    }

    /**
     * Rows of a grant's end the gate gives that the package refuses.
     *
     * @return iterable<string, array{?\Carbon\CarbonImmutable}>
     */
    public static function endsRefused(): iterable
    {
        yield 'no end' => [null];
        yield 'an end now' => [CarbonImmutable::parse('2026-11-01T12:00:00+00:00')];
        yield 'an end past' => [CarbonImmutable::parse('2026-11-01T11:59:59+00:00')];
    }

    /**
     * A grant the gate gives no end in the future is refused as the package's
     * own `not_fresh`.
     *
     * @param  ?\Carbon\CarbonImmutable  $until
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('endsRefused')]
    public function testAGrantWithNoEndInTheFutureIsRefused(?CarbonImmutable $until): void
    {
        CarbonImmutable::setTestNow('2026-11-01T12:00:00+00:00');

        $this->bind(new ScriptedFactorChangeGate($until));

        try {
            $this->granted(FactorChange::ADD_FACTOR);
            self::fail('A grant with no end in the future was expected to be refused.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::NOT_FRESH, $exception->reason);
            self::assertTrue($exception->byPackage);
        } finally {
            CarbonImmutable::setTestNow();
        }
    }

    /**
     * A grant lasts until the end the gate gives it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantLastsUntilTheGatesEnd(): void
    {
        $until = CarbonImmutable::now()->addMinutes(5);

        $this->bind(new ScriptedFactorChangeGate($until));

        self::assertSame($until, $this->granted(FactorChange::ADD_FACTOR));
    }

    /**
     * A bound gate's refusal is reported as the package's own, with its reason
     * and detail.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundGatesRefusalIsThePackages(): void
    {
        $this->bind(new ScriptedFactorChangeGate(refusal: new OperationRefusedException(FailureReason::LAST_FACTOR, 'The layer refuses.')));

        try {
            $this->allowed(FactorChange::GENERATE_RECOVERY_CODES);
            self::fail('The gate\'s refusal was expected.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::LAST_FACTOR, $exception->reason);
            self::assertSame('The layer refuses.', $exception->getMessage());
            self::assertTrue($exception->byPackage);
        }
    }

    /**
     * Anything else a bound gate throws propagates as it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundGatesFailurePropagates(): void
    {
        $failure = new \RuntimeException('The layer failed.');

        $this->bind(new ScriptedFactorChangeGate(refusal: $failure));

        try {
            $this->allowed(FactorChange::GENERATE_RECOVERY_CODES);
            self::fail('The gate\'s failure was expected.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
    }

    /**
     * A refusal a seam throws through the default gate stays the seam's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASeamsRefusalThroughTheDefaultStaysTheSeams(): void
    {
        $this->container()->instance(FreshnessGate::class, new RefusingFreshnessGate(1));

        $user = $this->person();

        $this->actingAs($user);

        try {
            DB::transaction(fn () => $this->changes()->allow($user, SignInProofs::APPLICATION, SignInProofs::SESSION, FactorChange::GENERATE_RECOVERY_CODES, new Collection));
            self::fail('The seam\'s refusal was expected.');
        } catch (OperationRefusedException $exception) {
            self::assertFalse($exception->byPackage);
        }
    }

    /**
     * Rows of a change asked the wrong way.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Enums\FactorChange, bool, string}>
     */
    public static function misaskedChanges(): iterable
    {
        yield 'a grant allowed' => [FactorChange::ADD_FACTOR, false, 'The change [mfa.add_factor] is a grant.'];
        yield 'a first factor allowed' => [FactorChange::ADD_FIRST_ADDITIONAL_FACTOR, false, 'The change [mfa.add_first_additional_factor] is a grant.'];
        yield 'a removal granted' => [FactorChange::REMOVE_FACTOR, true, 'The change [mfa.remove_factor] is not a grant.'];
        yield 'recovery codes granted' => [FactorChange::GENERATE_RECOVERY_CODES, true, 'The change [mfa.generate_recovery_codes] is not a grant.'];
    }

    /**
     * A grant is never asked as a change that is not one, nor the reverse.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @param  bool  $asGrant
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('misaskedChanges')]
    public function testAChangeIsAskedOnlyAsWhatItIs(FactorChange $change, bool $asGrant, string $message): void
    {
        $gate     = $this->bind(new ScriptedFactorChangeGate(CarbonImmutable::now()->addMinute()));
        $factorId = $change->namesFactor() ? 'factor-1' : null;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        try {
            DB::transaction(fn () => $asGrant
                ? $this->changes()->grant($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, $change, new Collection)
                : $this->changes()->allow($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, $change, new Collection, $factorId));
        } finally {
            self::assertSame([], $gate->requests);
        }
    }

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
     * Each change's operation, whether it names a factor, and whether it is a
     * grant.
     *
     * @return void
     */
    public function testWhatEachChangeIs(): void
    {
        self::assertNull(FactorChange::ADD_FIRST_ADDITIONAL_FACTOR->operation());
        self::assertSame(Operation::ADD_FACTOR, FactorChange::ADD_FACTOR->operation());
        self::assertSame(Operation::REMOVE_FACTOR, FactorChange::REMOVE_FACTOR->operation());
        self::assertSame(Operation::GENERATE_RECOVERY_CODES, FactorChange::GENERATE_RECOVERY_CODES->operation());

        self::assertSame([FactorChange::REMOVE_FACTOR], array_values(array_filter(FactorChange::cases(), static fn (FactorChange $change): bool => $change->namesFactor())));
        self::assertSame(
            [FactorChange::ADD_FIRST_ADDITIONAL_FACTOR, FactorChange::ADD_FACTOR],
            array_values(array_filter(FactorChange::cases(), static fn (FactorChange $change): bool => $change->isGrant())),
        );
    }

    /**
     * Ask for the grant for the person, inside a transaction.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return \Carbon\CarbonImmutable
     *
     * @throws \Throwable
     */
    private function granted(FactorChange $change): CarbonImmutable
    {
        return DB::transaction(fn (): CarbonImmutable => $this->changes()->grant($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, $change, new Collection));
    }

    /**
     * Ask for the change for the person, inside a transaction.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChange  $change
     * @return void
     *
     * @throws \Throwable
     */
    private function allowed(FactorChange $change): void
    {
        DB::transaction(fn () => $this->changes()->allow($this->person(), SignInProofs::APPLICATION, SignInProofs::SESSION, $change, new Collection));
    }

    /**
     * Bind the gate, and return it.
     *
     * @param  \Tests\Fixtures\Requirements\ScriptedFactorChangeGate  $gate
     * @return \Tests\Fixtures\Requirements\ScriptedFactorChangeGate
     */
    private function bind(ScriptedFactorChangeGate $gate): ScriptedFactorChangeGate
    {
        $this->container()->instance(FactorChangeGate::class, $gate);

        return $gate;
    }

    /**
     * A person.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function person(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'changes@example.test']);
    }

    /**
     * The service under test.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\FactorChanges
     */
    private function changes(): FactorChanges
    {
        return $this->container()->make(FactorChanges::class);
    }
}
