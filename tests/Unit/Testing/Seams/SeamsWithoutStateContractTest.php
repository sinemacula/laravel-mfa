<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\Operation;
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\ApplicationResolverContract;
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
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Requirements\FreshOnceGate;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FaultySeams;
use Tests\TestCase;

/**
 * The contract kits of the seams whose answers depend on no stored state: the
 * freshness gate, the identity and tenant requirements, the application, the
 * subject type, the event context and the session transition. Each proves the
 * package's default (or, for the application resolver, which has none, an
 * application's own), and rejects a faulty one.
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
#[CoversClass(EventContextResolverContract::class)]
#[CoversClass(SessionTransitionContract::class)]
#[CoversClass(SeamAssert::class)]
#[CoversClass(IdentityContractSubjectType::class)]
#[CoversClass(MiddlewareSessionTransition::class)]
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(IdentityContractRequirement::class)]
#[CoversClass(NoTenantRequirement::class)]
#[CoversClass(DefaultEventContextResolver::class)]
final class SeamsWithoutStateContractTest extends TestCase
{
    use ApplicationResolverTests, EventContextResolverTests, FreshnessGateTests, IdentityRequirementTests, SessionTransitionTests, SubjectTypeResolverTests, TenantRequirementTests;

    /**
     * The kit rejects a gate that finds everything fresh.
     *
     * @return void
     */
    public function testRejectsAGateThatFindsEverythingFresh(): void
    {
        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertANameThatIsNoOperationIsNeverFresh(new FaultySeams);
    }

    /**
     * The gates the kit rejects: one that always asks for nothing; one with a
     * requirement where neither side has any, however strict; one with none for
     * a caller who asks; and one that asks less than the caller.
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
                 * Fresh.
                 *
                 * @param  string  $operation
                 * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
                 * @return bool
                 */
                #[\Override]
                public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
                {
                    return true;
                }

                /**
                 * No deadline.
                 *
                 * @param  string  $operation
                 * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
                 * @return ?\Carbon\CarbonImmutable
                 */
                #[\Override]
                public function freshUntil(string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
                {
                    return null;
                }

                /**
                 * Nothing for no caller, and less than a caller asks.
                 *
                 * @param  string  $operation
                 * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
                 * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
                 */
                #[\Override]
                public function requirement(string $operation, ?Requirement $callerRequirement = null): ?Requirement
                {
                    return $callerRequirement === null ? null : Requirement::none();
                }
            },
        ];
    }

    /**
     * The kit rejects a gate that says it holds a session to anything but what
     * the operation and the caller ask.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FreshnessGate  $gate
     * @return void
     */
    #[DataProvider('gatesAskingTheWrongThing')]
    public function testRejectsAGateThatAsksTheWrongThing(FreshnessGate $gate): void
    {
        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertTheRequirementAsksWhatTheCallerAsks($gate);
    }

    /**
     * The kit rejects a gate whose deadline has already passed, and one that
     * names a deadline for an operation it does not find fresh.
     *
     * @return void
     */
    public function testRejectsAGateWithADeadlineThatIsNoDeadline(): void
    {
        try {
            FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh(new FaultySeams, Operation::ADD_FACTOR->value);

            self::fail('A deadline already past was expected to be rejected.');
        } catch (AssertionFailedError $failure) {
            self::assertStringContainsString('must not be in the past', $failure->getMessage());
        }

        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertADeadlineIsAheadAndMeansFresh(new FreshOnceGate, Operation::ADD_FACTOR->value);
    }

    /**
     * The kit rejects a gate that does not refuse an unbounded requirement.
     *
     * @return void
     */
    public function testRejectsAGateThatTakesAnUnboundedRequirement(): void
    {
        $this->expectException(AssertionFailedError::class);

        FreshnessGateContract::assertAnUnboundedRequirementIsRefused(new FaultySeams);
    }

    /**
     * The kit rejects a requirement that changes with every call.
     *
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
     * The kit rejects a blank application.
     *
     * @return void
     */
    public function testRejectsABlankApplication(): void
    {
        $this->expectException(AssertionFailedError::class);

        ApplicationResolverContract::assertNamesOneApplication(new FaultySeams, Request::create('/'));
    }

    /**
     * The kit rejects a resolver that finds a machine a person.
     *
     * @return void
     */
    public function testRejectsAResolverThatFindsAMachineAPerson(): void
    {
        $this->expectException(AssertionFailedError::class);

        SubjectTypeResolverContract::assertAMachineIsNotAPerson(new FaultySeams, $this->machineIdentity());
    }

    /**
     * The kit rejects a context that holds an object.
     *
     * @return void
     */
    public function testRejectsAContextHoldingAnObject(): void
    {
        $this->expectException(AssertionFailedError::class);

        SeamAssert::scalars(['identity_type' => 'person', 'identity_id' => new \stdClass], 'An event context must hold integers, strings and nulls only.');
    }

    /**
     * The kit rejects a transition that fails without refusing.
     *
     * @return void
     */
    public function testRejectsATransitionThatFailsWithoutRefusing(): void
    {
        $this->expectException(AssertionFailedError::class);

        SessionTransitionContract::assertReturnsOrRefusesByThrowing(new FaultySeams, $this->transitionIdentity(), 'web');
    }

    /**
     * The default transition returns and changes no proof.
     *
     * @return void
     */
    public function testTheDefaultTransitionChangesNothing(): void
    {
        $user  = $this->transitionIdentity();
        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record(SignInProofs::of($user)->password());

        $before = $store->proofs($user, 'web');

        self::assertCount(1, $before);

        (new MiddlewareSessionTransition)->returnToPending($user, 'web', Requirement::none()->withAdditionalVerification());

        self::assertSame($before[0]->toArray(), $store->proofs($user, 'web')[0]->toArray());
    }

    /**
     * An application's own resolver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver
     */
    #[\Override]
    protected function applicationResolver(): ApplicationResolver
    {
        return new HeaderApplicationResolver;
    }

    /**
     * A request for the `api` application.
     *
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function applicationRequest(): Request
    {
        return HeaderApplicationResolver::requestFor('api');
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    #[\Override]
    protected function eventContextResolver(): EventContextResolver
    {
        return $this->container()->make(EventContextResolver::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function eventIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * The bound default, asked for a signed-in person.
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
     * The bound default, asked for a person with a step-up just recorded.
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
        $store->record($proofs->password(60));
        $store->record($proofs->totp(30));

        return $this->container()->make(FreshnessGate::class);
    }

    /**
     * The package's operation every application has a freshness for.
     *
     * @return string
     */
    #[\Override]
    protected function freshOperation(): string
    {
        return Operation::ADD_FACTOR->value;
    }

    /**
     * The bound default.
     *
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
     * The application.
     *
     * @return string
     */
    #[\Override]
    protected function requirementApplication(): string
    {
        return 'web';
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    #[\Override]
    protected function sessionTransition(): SessionTransition
    {
        return $this->container()->make(SessionTransition::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function transitionIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'transition@example.test']);
    }

    /**
     * The application.
     *
     * @return string
     */
    #[\Override]
    protected function transitionApplication(): string
    {
        return 'web';
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver
     */
    #[\Override]
    protected function subjectTypeResolver(): SubjectTypeResolver
    {
        return $this->container()->make(SubjectTypeResolver::class);
    }

    /**
     * A person.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function personIdentity(): Authenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * A machine.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    protected function machineIdentity(): Authenticatable
    {
        return new NonEloquentIdentity('machine-1', person: false);
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     */
    #[\Override]
    protected function tenantRequirement(): TenantRequirement
    {
        return $this->container()->make(TenantRequirement::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function tenantIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * The application.
     *
     * @return string
     */
    #[\Override]
    protected function tenantApplication(): string
    {
        return 'web';
    }
}
