<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\IdentityContractActiveState;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\FactorChangeMade;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\SessionChange;
use SineMacula\Laravel\Mfa\Testing\Seams\ActiveStateResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\ApplicationResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ActiveStateResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ApplicationResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\EventContextResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\FreshnessGateTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\IdentityRequirementTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\SessionTransitionTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\SubjectTypeResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\TenantRequirementTests;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\FreshnessGateContract;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SeamAssert;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionTransitionContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SubjectTypeResolverContract;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Requirements\FreshOnceGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\AmbientSessionContextResolver;
use Tests\Fixtures\Seams\DriftingSeams;
use Tests\Fixtures\Seams\FaultySeams;
use Tests\Fixtures\Seams\FixedActiveState;
use Tests\Fixtures\Seams\ObjectContextResolver;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\Fixtures\Seams\ScriptedFreshnessGate;
use Tests\TestCase;

/**
 * Kits of the seams whose answers depend on no stored state. Each proves the
 * package's default or, for the application resolver, which has none, an
 * application's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessGateContract::class)]
#[CoversClass(RequirementSeamContract::class)]
#[CoversClass(ApplicationResolverContract::class)]
#[CoversClass(SubjectTypeResolverContract::class)]
#[CoversClass(ActiveStateResolverContract::class)]
#[CoversClass(EventContextResolverContract::class)]
#[CoversClass(SessionTransitionContract::class)]
#[CoversClass(SeamAssert::class)]
#[CoversClass(IdentityContractSubjectType::class)]
#[CoversClass(IdentityContractActiveState::class)]
#[CoversClass(MiddlewareSessionTransition::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(IdentityContractRequirement::class)]
#[CoversClass(NoTenantRequirement::class)]
#[CoversClass(DefaultEventContextResolver::class)]
final class SeamsWithoutStateContractTest extends TestCase
{
    use ActiveStateResolverTests,
        ApplicationResolverTests,
        EventContextResolverTests,
        FreshnessGateTests,
        IdentityRequirementTests,
        SessionTransitionTests,
        SubjectTypeResolverTests,
        TenantRequirementTests;

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
     * @return void
     */
    public function testRejectsABlankApplication(): void
    {
        $this->expectException(AssertionFailedError::class);

        ApplicationResolverContract::assertNamesOneApplication(new FaultySeams, Request::create('/'));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatFindsAMachineAPerson(): void
    {
        $this->expectException(AssertionFailedError::class);

        SubjectTypeResolverContract::assertAMachineIsNotAPerson(new FaultySeams, $this->machineIdentity());
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatFindsAnInactiveIdentityActive(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An inactive identity must not be active.');

        ActiveStateResolverContract::assertAnInactiveIdentityIsNotActive(new FixedActiveState(true), $this->inactiveIdentity());
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatFindsAnActiveIdentityInactive(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('An active identity must be active.');

        ActiveStateResolverContract::assertAnActiveIdentityIsActive(new FixedActiveState(false), $this->activeIdentity());
    }

    /**
     * @return void
     */
    public function testRejectsAContextHoldingAnObject(): void
    {
        $this->expectException(AssertionFailedError::class);

        SeamAssert::scalars(['identity_type' => 'person', 'identity_id' => new \stdClass], 'An event context must hold integers, strings and nulls only.');
    }

    /**
     * The session being served for a subject naming no sign-in or one it does
     * not know, or no session for a sign-in it was said to know.
     *
     * @return void
     */
    public function testRejectsAResolverThatNamesASessionItWasNotGiven(): void
    {
        $identity = new NonEloquentIdentity;
        $default  = new DefaultEventContextResolver;
        $ambient  = self::rejection(static fn () => EventContextResolverContract::assertNamesNoSessionItIsNotGiven(new AmbientSessionContextResolver, $identity));
        $unmapped = self::rejection(static fn () => EventContextResolverContract::assertNamesTheSessionOfAKnownSignIn($default, $identity, 'web', 'sign-in-1'));

        self::assertNotNull($ambient);
        self::assertStringContainsString('must leave `session_id` unknown', $ambient->getMessage());
        self::assertNotNull($unmapped);
        self::assertStringContainsString('must name its session', $unmapped->getMessage());
    }

    /**
     * The kit asks for the context of an identity and a request, and of
     * neither.
     *
     * @return void
     */
    public function testRejectsAResolverWithAnObjectInEitherContext(): void
    {
        foreach ([true, false] as $forIdentity) {
            $failure = self::rejection(static fn () => EventContextResolverContract::assertGivesScalarValuesOnly(new ObjectContextResolver($forIdentity), new NonEloquentIdentity));

            self::assertNotNull($failure, sprintf('A resolver with an object in the context %s was expected to be rejected.', $forIdentity ? 'of an identity' : 'of nobody'));
            self::assertStringContainsString('integers, strings and nulls only', $failure->getMessage());
        }
    }

    /**
     * Though never a blank one.
     *
     * @return void
     */
    public function testRejectsAResolverThatNamesAnotherApplicationEachTime(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A request must name the same application each time.');

        ApplicationResolverContract::assertNamesOneApplication(new DriftingSeams, Request::create('/'));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatFindsAPersonAMachine(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A person\'s identity must be a person.');

        SubjectTypeResolverContract::assertAPersonIsAPerson(new DriftingSeams, $this->personIdentity());
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
     * @return void
     */
    public function testRejectsATransitionThatFailsWithoutRefusing(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionTransitionContract::assertReturnsOrRefusesByThrowing(new FaultySeams, $this->sessionChange(...));
    }

    /**
     * Each arranged afresh.
     *
     * @return void
     */
    public function testTheKitJudgesEveryChangeWithAndWithoutAShortfall(): void
    {
        $transition = new RecordingSessionTransition;
        $arranged   = 0;

        SessionTransitionContract::assertReturnsOrRefusesByThrowing($transition, function (FactorChangeMade $change) use (&$arranged): SessionChange {
            $arranged++;

            return $this->sessionChange($change);
        });

        $judged = array_map(static fn (SessionChange $change): array => [$change->change, $change->outstanding !== null], $transition->changes);

        self::assertSame(6, $arranged);
        self::assertSame([
            [FactorChangeMade::CONFIRMED, true], [FactorChangeMade::CONFIRMED, false],
            [FactorChangeMade::PASSKEY_REGISTERED, true], [FactorChangeMade::PASSKEY_REGISTERED, false],
            [FactorChangeMade::REMOVED, true], [FactorChangeMade::REMOVED, false],
        ], $judged);
    }

    /**
     * @return void
     */
    public function testTheDefaultTransitionChangesNothing(): void
    {
        $user  = $this->transitionIdentity();
        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record($user, SignInProofs::of($user)->password());

        $before = $store->proofs($user, 'web', SignInProofs::SESSION);

        self::assertCount(1, $before);

        $change = $this->sessionChange(FactorChangeMade::CONFIRMED);
        $short  = new SessionChange($change->identity, $change->application, $change->session, $change->change, $change->factor, Requirement::none()->withAdditionalVerification());

        self::assertNull((new MiddlewareSessionTransition)->factorChanged($short));

        self::assertSame($before[0]->toArray(), $store->proofs($user, 'web', SignInProofs::SESSION)[0]->toArray());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver
     */
    #[\Override]
    protected function applicationResolver(): ApplicationResolver
    {
        return new HeaderApplicationResolver;
    }

    /**
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function applicationRequest(): Request
    {
        return HeaderApplicationResolver::requestFor('api');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    #[\Override]
    protected function eventContextResolver(): EventContextResolver
    {
        return $this->container()->make(EventContextResolver::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function eventIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * Asked for a signed-in person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    #[\Override]
    protected function freshnessGate(): FreshnessGate
    {
        $this->actingAs($this->transitionIdentity());

        return $this->container()->make(FreshnessGate::class);
    }

    /**
     * Asked for a person with a step-up just recorded.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    #[\Override]
    protected function freshGate(): FreshnessGate
    {
        $identity = TestUser::query()->create(['email' => 'fresh@example.test']);
        $store    = $this->container()->make(ProofStore::class);
        $proofs   = SignInProofs::of($identity);

        $this->actingAs($identity);

        $store->begin($identity, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record($identity, $proofs->password(60));
        $store->record($identity, $proofs->totp(30));

        return $this->container()->make(FreshnessGate::class);
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
     * @return \SineMacula\Laravel\Mfa\Contracts\IdentityRequirement
     */
    #[\Override]
    protected function identityRequirement(): IdentityRequirement
    {
        return $this->container()->make(IdentityRequirement::class);
    }

    /**
     * A person who requires an additional factor of their own.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function requiringIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity(requirement: Requirement::none()->withMultifactor());
    }

    /**
     * A person who requires nothing of their own.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function otherRequiringIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity('plain-2');
    }

    /**
     * @return string
     */
    #[\Override]
    protected function requirementApplication(): string
    {
        return 'web';
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    #[\Override]
    protected function sessionTransition(): SessionTransition
    {
        return $this->container()->make(SessionTransition::class);
    }

    /**
     * Made to a TOTP factor on a person's sign-in on `web`.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorChangeMade  $change
     * @return \SineMacula\Laravel\Mfa\Requirements\SessionChange
     */
    #[\Override]
    protected function sessionChange(FactorChangeMade $change): SessionChange
    {
        $factor = new FactorSummary('factor-totp', 'totp', null, null, FactorStatus::CONFIRMED, false, null);

        return new SessionChange($this->transitionIdentity(), 'web', SignInProofs::SESSION, $change, $factor, null);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver
     */
    #[\Override]
    protected function subjectTypeResolver(): SubjectTypeResolver
    {
        return $this->container()->make(SubjectTypeResolver::class);
    }

    /**
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function personIdentity(): Authenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function machineIdentity(): Authenticatable
    {
        return new NonEloquentIdentity('machine-1', person: false);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver
     */
    #[\Override]
    protected function activeStateResolver(): ActiveStateResolver
    {
        return $this->container()->make(ActiveStateResolver::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function activeIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function inactiveIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity('inactive-1', active: false);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     */
    #[\Override]
    protected function tenantRequirement(): TenantRequirement
    {
        return $this->container()->make(TenantRequirement::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function tenantIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * @return string
     */
    #[\Override]
    protected function tenantApplication(): string
    {
        return 'web';
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
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    private function transitionIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'transition@example.test']);
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
