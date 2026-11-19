<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FreshnessGateTests;
use SineMacula\Laravel\Mfa\Testing\Seams\FreshnessGateContract;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Requirements\FreshOnceGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\CallerBlindFreshnessGate;
use Tests\Fixtures\Seams\FaultyFreshnessGateKit;
use Tests\Fixtures\Seams\FaultySeams;
use Tests\Fixtures\Seams\ScriptedFreshnessGate;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessGateContract::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversTrait(FreshnessGateTests::class)]
final class FreshnessGateContractTest extends TestCase
{
    use FreshnessGateTests;

    /**
     * @return void
     */
    public function testRejectsAGateThatFindsEverythingFresh(): void
    {
        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertANameThatIsNoOperationIsNeverFresh(new FaultySeams, Callers::current());
    }

    /**
     * One that always asks nothing, one with a requirement where neither side
     * has any, one with none for a caller who asks, and one that asks less than
     * the caller.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Mfa\Contracts\FreshnessGate}>
     */
    public static function gatesAskingTheWrongThing(): iterable
    {
        yield 'asks for nothing' => [new FaultySeams];
        yield 'has a requirement of its own for anything' => [new FixedFreshnessGate(Requirement::none()->withAdditionalVerification(60))];
        yield 'has none for a caller who asks' => [new FixedFreshnessGate(null)];
        yield 'asks less than the caller' => [
            new class implements FreshnessGate {
                /**
                 * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
                 * @param  string  $operation
                 * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
                 * @return bool
                 */
                #[\Override]
                public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
                {
                    return true;
                }

                /**
                 * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
                 * @param  string  $operation
                 * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
                 * @return ?\Carbon\CarbonImmutable
                 */
                #[\Override]
                public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
                {
                    return null;
                }

                /**
                 * Nothing for no caller, and less than a caller asks.
                 *
                 * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
                 * @param  string  $operation
                 * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
                 * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
                 */
                #[\Override]
                public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement
                {
                    return $callerRequirement === null ? null : Requirement::none();
                }
            },
        ];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    #[DataProvider('gatesAskingTheWrongThing')]
    public function testRejectsAGateThatAsksTheWrongThing(FreshnessGate $gate): void
    {
        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertTheRequirementAsksWhatTheCallerAsks($gate, Callers::current());
    }

    /**
     * One whose deadline has passed, and one with a deadline for an operation
     * it does not find fresh.
     *
     * @return void
     */
    public function testRejectsAGateWithADeadlineThatIsNoDeadline(): void
    {
        try {
            FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh(new FaultySeams, Callers::current(), Operation::ADD_FACTOR->value);

            self::fail('A deadline already past was expected to be rejected.');
        } catch (AssertionFailedError $failure) {
            self::assertStringContainsString('must not be in the past', $failure->getMessage());
        }

        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh(new FreshOnceGate, Callers::current(), Operation::ADD_FACTOR->value);
    }

    /**
     * @return void
     */
    public function testRejectsAGateThatTakesAnUnboundedRequirement(): void
    {
        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertAnUnboundedRequirementIsRefused(new FaultySeams, Callers::current());
    }

    /**
     * @return void
     */
    public function testRejectsAGateThatFindsAnUnconfiguredOperationFresh(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An operation with no requirement must never be fresh.');

        FreshnessGateContract::assertAnOperationWithNoRequirementIsNeverFresh(new ScriptedFreshnessGate(true, null), Callers::current());
    }

    /**
     * Fresh with no deadline, or a deadline without being fresh.
     *
     * @return void
     */
    public function testRejectsAGateWhoseFreshnessAndDeadlineDisagree(): void
    {
        $gates = [
            'fresh with no deadline'    => new ScriptedFreshnessGate(true, null),
            'not fresh with a deadline' => new ScriptedFreshnessGate(false, CarbonImmutable::now()->addHour()),
        ];

        foreach ($gates as $name => $gate) {
            self::assertNotNull(
                self::rejection(static fn () => FreshnessGateContract::assertAnOperationThatIsNotFreshHasNoDeadline($gate, Callers::current())),
                sprintf('A gate %s was expected to be rejected.', $name),
            );
        }
    }

    /**
     * Failing its assertion rather than erring.
     *
     * @return void
     */
    public function testRejectsAGateThatNamesNoDeadline(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A session fresh for the operation must say until when.');

        FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh(new ScriptedFreshnessGate(true, null), Callers::current(), Operation::ADD_FACTOR->value);
    }

    /**
     * One blind to it when judging whether the session is fresh, and one when
     * saying until when.
     *
     * @return iterable<string, array{bool, bool, string}>
     */
    public static function gatesIgnoringTheCaller(): iterable
    {
        yield 'fresh whatever the caller asks' => [true, false, 'must not be fresh for a stricter requirement'];
        yield 'with a deadline whatever the caller asks' => [false, true, 'must have no deadline'];
    }

    /**
     * @param  bool  $blindFresh
     * @param  bool  $blindUntil
     * @param  string  $message
     * @return void
     */
    #[DataProvider('gatesIgnoringTheCaller')]
    public function testRejectsAGateThatIgnoresTheCallersRequirement(bool $blindFresh, bool $blindUntil, string $message): void
    {
        $gate = new CallerBlindFreshnessGate($this->freshGate(), $blindFresh, $blindUntil);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage($message);

        FreshnessGateContract::assertTheCallersStricterRequirementApplies($gate, Callers::current(), $this->freshOperation());
    }

    /**
     * @return void
     */
    public function testTheKitRejectsAGateThatFindsEverythingFresh(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not be fresh for a stricter requirement');

        (new FaultyFreshnessGateKit('kit'))->testFreshnessGateAppliesTheCallersStricterRequirement();
    }

    /**
     * A verification exactly as old as the caller allows still counts.
     *
     * @return iterable<string, array{int, bool}>
     */
    public static function verificationAges(): iterable
    {
        yield '10 seconds old' => [10, false];
        yield '11 seconds old' => [11, true];
    }

    /**
     * @param  int  $secondsAgo
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('verificationAges')]
    public function testTheCallersRequirementAsksForAVerificationInTheLast10Seconds(int $secondsAgo, bool $accepted): void
    {
        $this->freezeTime();

        $gate  = $this->gateVerified($secondsAgo);
        $check = fn () => FreshnessGateContract::assertTheCallersStricterRequirementApplies($gate, Callers::current(), $this->freshOperation());

        self::assertSame($accepted, self::rejection($check) === null);
    }

    /**
     * Which no caller's requirement can make stricter.
     *
     * @return void
     */
    public function testRejectsAGateThatIsNeverFresh(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must be fresh without a caller\'s requirement');

        FreshnessGateContract::assertTheCallersStricterRequirementApplies(new ScriptedFreshnessGate(false, null), Callers::current(), $this->freshOperation());
    }

    /**
     * Asked for a signed-in person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    #[\Override]
    protected function freshnessGate(): FreshnessGate
    {
        $this->actingAs(TestUser::query()->firstOrCreate(['email' => 'signed-in@example.test']));

        return $this->container()->make(FreshnessGate::class);
    }

    /**
     * Asked for a person with a step-up recorded 30 seconds ago.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    #[\Override]
    protected function freshGate(): FreshnessGate
    {
        return $this->gateVerified(30);
    }

    /**
     * The package's operation, which every application has a freshness for.
     *
     * @return string
     */
    #[\Override]
    protected function freshOperation(): string
    {
        return Operation::ADD_FACTOR->value;
    }

    /**
     * As the gate last signed it in.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function freshnessCaller(): CallerContext
    {
        return Callers::current();
    }

    /**
     * Asked for a person with a step-up recorded `$secondsAgo` seconds ago.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    private function gateVerified(int $secondsAgo): FreshnessGate
    {
        $identity = TestUser::query()->create(['email' => 'fresh@example.test']);
        $store    = $this->container()->make(ProofStore::class);
        $proofs   = SignInProofs::of($identity);

        $this->actingAs($identity);

        $store->begin($identity, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record($identity, $proofs->password(60));
        $store->record($identity, $proofs->totp($secondsAgo));

        return $this->container()->make(FreshnessGate::class);
    }

    /**
     * `null` when the check accepts what it is given.
     *
     * @param  \Closure(): void  $check
     * @return ?\PHPUnit\Framework\AssertionFailedError
     */
    private static function rejection(\Closure $check): ?AssertionFailedError
    {
        try {
            $check();
        } catch (AssertionFailedError $failure) {
            return $failure;
        }

        return null;
    }
}
