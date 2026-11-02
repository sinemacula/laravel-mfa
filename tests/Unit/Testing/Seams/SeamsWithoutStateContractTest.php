<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
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
use SineMacula\Laravel\Mfa\Http\MiddlewareSessionTransition;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\ApplicationResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\ApplicationResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\FreshnessGateContract;
use SineMacula\Laravel\Mfa\Testing\Seams\FreshnessGateTests;
use SineMacula\Laravel\Mfa\Testing\Seams\IdentityRequirementTests;
use SineMacula\Laravel\Mfa\Testing\Seams\RequirementSeamContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SeamAssert;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionTransitionContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionTransitionTests;
use SineMacula\Laravel\Mfa\Testing\Seams\SubjectTypeResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SubjectTypeResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\TenantRequirementTests;
use Tests\Fixtures\Drivers\HeaderApplicationResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
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

        RequirementSeamContract::assertKeepsNoStateBetweenCalls(static fn () => $faulty->requirementFor($identity, 'web'), static fn () => $faulty->requirementFor($identity, 'api'));
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

        self::assertEquals($before, $store->proofs($user, 'web'));
    }

    /**
     * An application's own resolver.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver
     */
    protected function applicationResolver(): ApplicationResolver
    {
        return new HeaderApplicationResolver;
    }

    /**
     * A request for the `api` application.
     *
     * @return \Illuminate\Http\Request
     */
    protected function applicationRequest(): Request
    {
        return HeaderApplicationResolver::requestFor('api');
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    protected function eventContextResolver(): EventContextResolver
    {
        return $this->container()->make(EventContextResolver::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function eventIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * The bound default, asked for a signed-in person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    protected function freshnessGate(): FreshnessGate
    {
        $this->actingAs($this->transitionIdentity());

        return $this->container()->make(FreshnessGate::class);
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\IdentityRequirement
     */
    protected function identityRequirement(): IdentityRequirement
    {
        return $this->container()->make(IdentityRequirement::class);
    }

    /**
     * A person who requires an additional factor of their own.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function requiringIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity(requirement: Requirement::none()->withMultifactor());
    }

    /**
     * A person who requires nothing of their own.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function otherRequiringIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity('plain-2');
    }

    /**
     * The application.
     *
     * @return string
     */
    protected function requirementApplication(): string
    {
        return 'web';
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionTransition
     */
    protected function sessionTransition(): SessionTransition
    {
        return $this->container()->make(SessionTransition::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
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
    protected function transitionApplication(): string
    {
        return 'web';
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver
     */
    protected function subjectTypeResolver(): SubjectTypeResolver
    {
        return $this->container()->make(SubjectTypeResolver::class);
    }

    /**
     * A person.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function personIdentity(): Authenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * A machine.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    protected function machineIdentity(): Authenticatable
    {
        return new NonEloquentIdentity('machine-1', person: false);
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     */
    protected function tenantRequirement(): TenantRequirement
    {
        return $this->container()->make(TenantRequirement::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function tenantIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * The application.
     *
     * @return string
     */
    protected function tenantApplication(): string
    {
        return 'web';
    }
}
