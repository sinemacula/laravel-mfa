<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionTransition;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Http\Middleware\ExemptFromMfa;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Exceptions\InvalidPendingCredentialException;
use Tests\Fixtures\Http\NeverFreshGate;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Lifecycle\FixedFreshnessGate;
use Tests\Fixtures\Requirements\FixedActiveTenant;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\FixedIdentityRequirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\RecordingSessionTransition;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * The `mfa` route middleware through the HTTP kernel: what it asks for, whose
 * proofs it judges, who it refuses, and which routes it lifts for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EnsureMfaRequirementIsMet::class)]
#[CoversClass(ExemptFromMfa::class)]
#[CoversClass(InsufficientAuthenticationException::class)]
#[CoversClass(RequirementService::class)]
final class EnsureMfaRequirementIsMetTest extends TestCase
{
    use ArrangesVerification;

    /** @var string A route that asks only for the composed requirement. */
    private const string BARE = 'gate/bare';

    /** @var string A route that asks for AAL2. */
    private const string LEVEL = 'gate/level';

    /** @var string A route that asks for a configured operation's freshness. */
    private const string OPERATION = 'gate/operation';

    /** @var string A route that asks for both. */
    private const string BOTH = 'gate/both';

    /** @var string The operation the routes name. */
    private const string CLOSE_BOOKS = 'billing.close_books';

    /** @var array<string, array<string, ?string>> The serialised form of asking for AAL2 at any age. */
    private const array AAL2 = ['minimum_level' => ['level' => 'aal2', 'max_age' => null]];

    /** @var array<string, array<string, ?int>> The serialised form of asking for an additional verification at any age. */
    private const array VERIFIED = ['additional_verification' => ['max_age' => null]];

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * `never` adds nothing: a person with no further proof passes bare `mfa`.
     *
     * @return void
     */
    public function testTheNeverModeAddsNothing(): void
    {
        $this->enableApplication(['requirement' => 'never']);

        $this->signedInPerson();

        $this->get(self::BARE)->assertOk();
    }

    /**
     * `enrolled` asks nothing of a person with no confirmed factor, so a shared
     * route group does not lock out people using optional MFA.
     *
     * @return void
     */
    public function testTheEnrolledModeAsksNothingWithoutAFactor(): void
    {
        $this->enableApplication(['requirement' => 'enrolled']);

        $this->signedInPerson();

        $this->get(self::BARE)->assertOk();
    }

    /**
     * `enrolled` asks a person with a confirmed factor to verify.
     *
     * @return void
     */
    public function testTheEnrolledModeAsksAPersonWithAFactor(): void
    {
        $this->enableApplication(['requirement' => 'enrolled']);

        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $refusal = $this->refusal(self::BARE);

        self::assertSame(self::VERIFIED, $refusal->requirement->toArray());
        self::assertTrue($refusal->hasConfirmedFactor);

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->get(self::BARE)->assertOk();
    }

    /**
     * `always` asks a person with no factor too, and says they have none.
     *
     * @return void
     */
    public function testTheAlwaysModeAsksAPersonWithNoFactor(): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $this->signedInPerson();

        $refusal = $this->refusal(self::BARE);

        self::assertSame(self::VERIFIED, $refusal->requirement->toArray());
        self::assertFalse($refusal->hasConfirmedFactor);
        self::assertSame([], $refusal->offered);
    }

    /**
     * The identity's own requirement applies under `never`.
     *
     * @return void
     */
    public function testAnIdentitysRequirementAppliesUnderNever(): void
    {
        $this->enableApplication(['requirement' => 'never']);

        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)));

        $this->signedInPerson();

        self::assertSame(self::AAL2, $this->refusal(self::BARE)->requirement->toArray());
    }

    /**
     * After a reset, the re-enrolment obligation is refused on every route that
     * carries `mfa`, also under `never`.
     *
     * @return void
     */
    public function testTheReenrollmentObligationIsRefused(): void
    {
        $this->enableApplication(['requirement' => 'never']);

        $user = $this->signedInPerson();

        $this->get(self::BARE)->assertOk();

        Mfa::resetIdentity($user, new Actor('admin', '9'), 'lost device');

        self::assertSame(self::VERIFIED, $this->refusal(self::BARE)->requirement->toArray());
    }

    /**
     * The active tenant's requirement applies through the resolver.
     *
     * @return void
     */
    public function testAnActiveTenantsRequirementApplies(): void
    {
        $tenants = self::createStub(TenantRequirement::class);

        $tenants->method('requirementFor')->willReturn(Requirement::none()->withPhishingResistance());

        $this->container()->instance(TenantRequirement::class, $tenants);
        $this->container()->instance(ActiveTenantResolver::class, new FixedActiveTenant('tenant-1'));

        $this->signedInPerson();

        self::assertSame(['phishing_resistance' => ['max_age' => null]], $this->refusal(self::BARE)->requirement->toArray());
    }

    /**
     * A password and a TOTP code make AAL2, so they pass the level.
     *
     * @return void
     */
    public function testAPasswordAndTotpPassTheLevel(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->get(self::LEVEL)->assertOk();
    }

    /**
     * A password and an email code are accepted without reaching AAL2, so they
     * do not.
     *
     * @return void
     */
    public function testAPasswordAndEmailDoNotPassTheLevel(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->email()]);

        self::assertSame(self::AAL2, $this->refusal(self::LEVEL)->requirement->toArray());
    }

    /**
     * Where a maximum age bounds the level, a fresh weaker proof never
     * refreshes an old stronger one.
     *
     * @return void
     */
    public function testAFreshWeakerProofDoesNotRefreshAnOldStrongerOne(): void
    {
        $this->container()->instance(IdentityRequirement::class, new FixedIdentityRequirement(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 300)));

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(600), $signIn->email()]);

        self::assertSame(['minimum_level' => ['level' => 'aal2', 'max_age' => 300]], $this->refusal(self::BARE)->requirement->toArray());

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->totp(30)]);

        $this->get(self::BARE)->assertOk();
    }

    /**
     * A first-factor passkey that observed user verification is multi-factor on
     * its own, so it needs no further proof for an additional verification or
     * for the level.
     *
     * @return void
     */
    public function testAMultiFactorFirstFactorPassesAlone(): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->passkey(true)]);

        $this->get(self::BARE)->assertOk();
        $this->get(self::LEVEL)->assertOk();
    }

    /**
     * A further proof alone is nothing without the first factor it follows.
     *
     * @return void
     */
    public function testAnAbsentFirstFactorIsRefused(): void
    {
        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(null));

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->totp()]);

        self::assertSame(self::AAL2, $this->refusal(self::LEVEL)->requirement->toArray());
    }

    /**
     * More than one first factor cannot say which sign-in the proofs belong to.
     *
     * @return void
     */
    public function testMoreThanOneFirstFactorIsRefused(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->passkey(true, 30), $signIn->totp()]);

        self::assertSame(self::AAL2, $this->refusal(self::LEVEL)->requirement->toArray());
    }

    /**
     * A proof dated after now does not count.
     *
     * @return void
     */
    public function testAFutureDatedProofDoesNotCount(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp(-60)]);

        self::assertSame(self::AAL2, $this->refusal(self::LEVEL)->requirement->toArray());
    }

    /**
     * Within the operation's maximum age a proof passes, and past it the
     * exception names the operation and carries its requirement.
     *
     * @return void
     */
    public function testAnOperationIsFreshOnlyWithinItsMaximumAge(): void
    {
        $this->configureTheOperation();

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(600)]);

        $refusal = $this->refusal(self::OPERATION);

        self::assertSame(self::CLOSE_BOOKS, $refusal->operation);
        self::assertSame(['additional_verification' => ['max_age' => 300]], $refusal->requirement->toArray());
        self::assertSame(300, $refusal->maxAge());

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->totp(30)]);

        $this->get(self::OPERATION)->assertOk();
    }

    /**
     * An operation with no requirement is not a misconfiguration: it is simply
     * never fresh, and is answered with the exception rather than a server
     * error.
     *
     * @return void
     */
    public function testAnUnconfiguredOperationIsRefusedNotAServerError(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $refusal = $this->refusal(self::OPERATION);

        self::assertSame(self::CLOSE_BOOKS, $refusal->operation);
        self::assertSame([], $refusal->requirement->toArray());

        $this->get(self::OPERATION)->assertUnauthorized();
    }

    /**
     * A bound gate that supplies an operation the local configuration does not
     * name decides it.
     *
     * @return void
     */
    public function testABoundGateMaySupplyAnOperation(): void
    {
        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(null));

        $this->signedInPerson();

        $this->get(self::OPERATION)->assertOk();
    }

    /**
     * A gate that says not fresh refuses, though the proofs meet the
     * requirement, and its own requirement goes on the exception.
     *
     * @return void
     */
    public function testAGateSayingNotFreshRefusesWhileTheCheckPasses(): void
    {
        $this->container()->instance(FreshnessGate::class, new NeverFreshGate(Requirement::none()->withMultifactor(60)));

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->get(self::LEVEL)->assertOk();

        $refusal = $this->refusal(self::OPERATION);

        self::assertSame(['multifactor' => ['max_age' => 60]], $refusal->requirement->toArray());
    }

    /**
     * A gate with no requirement of its own leaves the composed one on the
     * exception.
     *
     * @return void
     */
    public function testAGateWithNoRequirementLeavesTheComposedOne(): void
    {
        $this->container()->instance(FreshnessGate::class, new NeverFreshGate);
        $this->enableApplication(['requirement' => 'always']);

        $this->signedInPerson();

        self::assertSame(self::VERIFIED, $this->refusal(self::OPERATION)->requirement->toArray());
    }

    /**
     * A level and an operation together: a fresh proof that does not reach the
     * level is refused, and the exception carries the strictest of them.
     *
     * @return void
     */
    public function testALevelRefusesThoughTheOperationIsFresh(): void
    {
        $this->configureTheOperation();

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->email(30)]);

        $this->get(self::OPERATION)->assertOk();

        $refusal = $this->refusal(self::BOTH);

        self::assertSame(['additional_verification' => ['max_age' => 300], ...self::AAL2], $refusal->requirement->toArray());
        self::assertSame(self::CLOSE_BOOKS, $refusal->operation);
    }

    /**
     * The other way: the level met long ago does not make the operation fresh,
     * and a proof that makes both passes.
     *
     * @return void
     */
    public function testAnOperationRefusesThoughTheLevelIsMet(): void
    {
        $this->configureTheOperation();

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->totp(600)]);

        $this->get(self::LEVEL)->assertOk();

        self::assertSame(['additional_verification' => ['max_age' => 300], ...self::AAL2], $this->refusal(self::BOTH)->requirement->toArray());

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->totp(30)]);

        $this->get(self::BOTH)->assertOk();
    }

    /**
     * Separate `mfa` entries, as from a group and a route, each enforce their
     * own.
     *
     * @return void
     */
    public function testSeparateEntriesEachEnforceTheirOwn(): void
    {
        $this->configureTheOperation();

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(3600), $signIn->email(30)]);

        $this->get(self::OPERATION)->assertOk();

        self::assertSame(self::AAL2, $this->refusal('gate/stacked')->requirement->toArray());
    }

    /**
     * Who the package does not serve.
     *
     * @return iterable<string, array{0: \Closure(): ?\Illuminate\Contracts\Auth\Authenticatable, 1: bool}>
     */
    public static function unservedCallers(): iterable
    {
        yield 'a guest' => [static fn (): ?Authenticatable => null, false];
        yield 'a machine' => [static fn (): Authenticatable => new NonEloquentIdentity('robot-1', mfaEnabled: true, person: false), false];
        yield 'an identity that is not MFA-capable' => [static fn (): Authenticatable => PlainUser::query()->create(['email' => 'plain@example.test']), false];
    }

    /**
     * Whoever the package does not serve is refused with nothing from the gate,
     * under `never` too, since that setting controls the requirement and not
     * who is served.
     *
     * @param  \Closure(): ?\Illuminate\Contracts\Auth\Authenticatable  $caller
     * @param  bool  $hasConfirmedFactor
     * @return void
     */
    #[DataProvider('unservedCallers')]
    public function testACallerNotServedIsRefused(\Closure $caller, bool $hasConfirmedFactor): void
    {
        $this->configureTheOperation();

        $identity = $caller();

        if ($identity !== null) {
            $this->actingAs($identity);
        }

        $bare  = $this->refusal(self::BARE);
        $level = $this->refusal(self::BOTH);

        self::assertSame([], $bare->requirement->toArray());
        self::assertSame([], $bare->offered);
        self::assertSame($hasConfirmedFactor, $bare->hasConfirmedFactor);
        self::assertNull($bare->operation);

        self::assertSame(self::AAL2, $level->requirement->toArray());
        self::assertSame(self::CLOSE_BOOKS, $level->operation);
    }

    /**
     * An inactive identity is refused under `never`, and whatever an operation
     * would ask is read for the exception, though no gate is judged.
     *
     * @return void
     */
    public function testAnInactiveIdentityIsRefused(): void
    {
        $this->configureTheOperation();

        $this->actingAs(new NonEloquentIdentity('person-1', mfaEnabled: true, active: false));

        $bare      = $this->refusal(self::BARE);
        $operation = $this->refusal(self::OPERATION);

        self::assertSame([], $bare->requirement->toArray());
        self::assertTrue($bare->hasConfirmedFactor);
        self::assertSame([], $bare->offered);
        self::assertSame(['additional_verification' => ['max_age' => 300]], $operation->requirement->toArray());
    }

    /**
     * A pending session is refused, carrying what it owes and any level the
     * route asks; an operation is named but no gate is asked for it.
     *
     * @return void
     */
    public function testAPendingSessionIsRefused(): void
    {
        $this->configureTheOperation();

        $user = $this->person();

        $this->totpFactor($user);
        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        $bare = $this->refusal(self::BARE);
        $both = $this->refusal(self::BOTH);

        self::assertSame(self::VERIFIED, $bare->requirement->toArray());
        self::assertTrue($bare->hasConfirmedFactor);
        self::assertCount(1, $bare->offered);
        self::assertContainsOnlyInstancesOf(FactorSummary::class, $bare->offered);

        self::assertSame([...self::VERIFIED, ...self::AAL2], $both->requirement->toArray());
        self::assertSame(self::CLOSE_BOOKS, $both->operation);
    }

    /**
     * A pending session that may not list factors is offered none, and its
     * person's having no factor is reported as it is.
     *
     * @return void
     */
    public function testAPendingSessionThatMayNotListIsOfferedNothing(): void
    {
        $user = $this->person();

        $this->pendingSession($user, Requirement::none()->withAdditionalVerification(), [PendingAction::VERIFY]);

        $refusal = $this->refusal(self::BARE);

        self::assertSame([], $refusal->offered);
        self::assertFalse($refusal->hasConfirmedFactor);
    }

    /**
     * A request carrying a pending credential is never answered from the
     * guard's user, also when that user has met everything.
     *
     * @return void
     */
    public function testAPendingCredentialWinsOverAnActiveOne(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->get(self::LEVEL)->assertOk();

        $this->pendingSession($user, Requirement::none()->withAdditionalVerification());

        self::assertSame(self::VERIFIED, $this->refusal(self::BARE)->requirement->toArray());
    }

    /**
     * A pending credential that does not validate is not disguised as a
     * refusal.
     *
     * @return void
     */
    public function testAnInvalidPendingCredentialPropagates(): void
    {
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(invalid: true));

        $this->withoutExceptionHandling();

        $this->expectException(InvalidPendingCredentialException::class);

        $this->get(self::BARE);
    }

    /**
     * Each form of parameter the middleware refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function malformedParameters(): iterable
    {
        yield 'an unknown key' => ['mfa:scope=aal2'];
        yield 'a key in the wrong case' => ['mfa:LEVEL=aal2'];
        yield 'a repeated level' => ['mfa:level=aal1,level=aal2'];
        yield 'a repeated operation' => ['mfa:operation=one,operation=two'];
        yield 'a trailing comma' => ['mfa:level=aal2,'];
        yield 'nothing after the colon' => ['mfa:'];
        yield 'no key' => ['mfa:=aal2'];
        yield 'an empty level' => ['mfa:level='];
        yield 'an empty operation' => ['mfa:operation='];
        yield 'a second equals sign' => ['mfa:level=aal2=aal3'];
        yield 'the unclassified level' => ['mfa:level=unclassified'];
        yield 'a level that is not one' => ['mfa:level=aal9'];
        yield 'an operation out of form' => ['mfa:operation=Billing.Close'];
        yield 'a number of minutes' => ['mfa:5'];
        yield 'zero minutes' => ['mfa:0'];
    }

    /**
     * Whatever is malformed is refused at once with the same exception, also on
     * an exempt route, so a typo is loud.
     *
     * @param  string  $middleware
     * @return void
     */
    #[DataProvider('malformedParameters')]
    public function testMalformedParametersAreRefused(string $middleware): void
    {
        $this->signedInPerson();

        $this->container()->make(Router::class)->get('gate/malformed', self::reached(...))->middleware($middleware);

        $this->withoutExceptionHandling();

        $this->expectException(\InvalidArgumentException::class);

        $this->get('gate/malformed');
    }

    /**
     * The same malformed parameters on an exempt route.
     *
     * @param  string  $middleware
     * @return void
     */
    #[DataProvider('malformedParameters')]
    public function testMalformedParametersAreRefusedOnAnExemptRoute(string $middleware): void
    {
        $this->signedInPerson();

        $this->container()->make(Router::class)->get('gate/malformed', self::reached(...))->middleware([$middleware, 'mfa.exempt']);

        $this->withoutExceptionHandling();

        $this->expectException(\InvalidArgumentException::class);

        $this->get('gate/malformed');
    }

    /**
     * Each form of parameter the middleware accepts.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function wellFormedParameters(): iterable
    {
        yield 'a level' => ['mfa:level=aal1'];
        yield 'an operation' => ['mfa:operation=reports.export_all'];
        yield 'both' => ['mfa:level=aal2,operation=reports.export_all'];
        yield 'both the other way' => ['mfa:operation=reports.export_all,level=aal2'];
    }

    /**
     * Well-formed parameters are accepted at every level, in either order.
     *
     * @param  string  $middleware
     * @return void
     */
    #[DataProvider('wellFormedParameters')]
    public function testWellFormedParametersAreAccepted(string $middleware): void
    {
        $this->container()->instance(FreshnessGate::class, new FixedFreshnessGate(null));

        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->container()->make(Router::class)->get('gate/formed', self::reached(...))->middleware($middleware);

        $this->get('gate/formed')->assertOk();
    }

    /**
     * Routes the marker lifts the gate for, however it reached them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function exemptRoutes(): iterable
    {
        yield 'on the route' => ['gate/exempt'];
        yield 'on the route, ahead of the gate' => ['gate/exempt-first'];
        yield 'with a level' => ['gate/exempt-level'];
        yield 'a group after a gated group' => ['gate/exempt-group-after'];
        yield 'a group before a gated group' => ['gate/exempt-group-before'];
        yield 'by its class name' => ['gate/exempt-class'];
    }

    /**
     * The marker on the route lifts `mfa`, in any form, for a person who has
     * proved nothing and for a guest.
     *
     * @param  string  $uri
     * @return void
     */
    #[DataProvider('exemptRoutes')]
    public function testTheMarkerLiftsTheGate(string $uri): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $this->get($uri)->assertOk();

        $this->signedInPerson();

        $this->get($uri)->assertOk();
    }

    /**
     * A route that takes the marker away again is gated.
     *
     * @return void
     */
    public function testTheMarkerTakenOffIsNotAnExemption(): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $this->signedInPerson();

        self::assertSame(self::VERIFIED, $this->refusal('gate/exempt-excluded')->requirement->toArray());
    }

    /**
     * The marker grants nothing on any other route.
     *
     * @return void
     */
    public function testTheMarkerOnAnotherRouteGrantsNothing(): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $this->signedInPerson();

        $this->get('gate/exempt')->assertOk();

        self::assertSame(self::VERIFIED, $this->refusal(self::BARE)->requirement->toArray());
    }

    /**
     * With no matched route nothing is exempt, so the middleware does not
     * belong in the global stack.
     *
     * @return void
     */
    public function testNoMatchedRouteIsNotExempt(): void
    {
        $this->expectException(InsufficientAuthenticationException::class);

        $this->handleDirectly();
    }

    /**
     * `['mfa', 'auth:api']` authenticates first, whichever order the route
     * names them: the `api` identity is judged, not the default guard's.
     *
     * @return void
     */
    public function testTheIdentityOfTheNamedGuardIsJudgedWhenItIsMet(): void
    {
        $this->arrangeTwoGuards(apiProved: true);

        $this->get('gate/guarded')->assertOk();
    }

    /**
     * The same when the `api` identity is the one that falls short, though the
     * default guard's has met everything.
     *
     * @return void
     */
    public function testTheIdentityOfTheNamedGuardIsJudgedWhenItFallsShort(): void
    {
        $this->arrangeTwoGuards(apiProved: false);

        self::assertSame(self::AAL2, $this->refusal('gate/guarded')->requirement->toArray());
    }

    /**
     * The gate only reads: a shortfall is answered without any transition, so a
     * GET never changes a session.
     *
     * @return void
     */
    public function testTheGateNeverTransitionsASession(): void
    {
        $transition = new RecordingSessionTransition;

        $this->container()->instance(SessionTransition::class, $transition);
        $this->enableApplication(['requirement' => 'always']);

        $this->signedInPerson();

        self::assertSame(self::VERIFIED, $this->refusal(self::BARE)->requirement->toArray());
        self::assertSame([], $transition->returned);
    }

    /**
     * One resolved instance answers for whoever each request serves, so
     * consecutive requests share no answer.
     *
     * @return void
     */
    public function testOneInstanceSharesNoAnswerBetweenRequests(): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $proved   = $this->signedInPerson();
        $unproved = $this->person('other@example.test');

        $this->prove($proved, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->container()->make(ProofStore::class)->begin($unproved, self::APPLICATION, 'sign-in-b');

        $instance = $this->container()->make(EnsureMfaRequirementIsMet::class);

        self::assertSame('reached', $this->handleDirectly($instance)->getContent());

        $this->actingAs($unproved);

        try {
            $this->handleDirectly($instance);

            self::fail('The second identity has proved nothing.');
        } catch (InsufficientAuthenticationException $refusal) {
            self::assertSame([...self::VERIFIED, ...self::AAL2], $refusal->requirement->toArray());
        }

        $this->actingAs($proved);

        self::assertSame('reached', $this->handleDirectly($instance)->getContent());
    }

    /**
     * Without a sign-in, what the store cannot show does not pass.
     *
     * @return void
     */
    public function testNoSignInIsRefusedAtALevel(): void
    {
        $this->actingAs($this->person());

        self::assertSame(self::AAL2, $this->refusal(self::LEVEL)->requirement->toArray());
    }

    /**
     * The kernel's default rendering of a refusal is a 401 with no factor
     * detail and no challenge header.
     *
     * @return void
     */
    public function testTheDefaultRenderingIsA401WithNoFactorDetail(): void
    {
        config()->set('app.debug', false);

        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $this->enableApplication(['requirement' => 'always']);

        $response = $this->getJson(self::BARE);

        $response->assertUnauthorized();
        $response->assertExactJson(['message' => InsufficientAuthenticationException::MESSAGE]);
        $response->assertHeaderMissing('WWW-Authenticate');
    }

    /**
     * A renderable an application may write gives the RFC 9470 answer, with its
     * factors masked.
     *
     * @return void
     */
    public function testAnApplicationCanAnswerAsTheRfcDescribes(): void
    {
        $user = $this->signedInPerson();

        $this->emailFactor($user);

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60)]);

        $refusal = $this->refusal(self::LEVEL);

        $description = InsufficientAuthenticationException::MESSAGE;

        self::assertSame('Bearer error="insufficient_user_authentication", error_description="' . $description . '", acr_values="aal2"', $refusal->wwwAuthenticate());

        self::assertCount(1, $refusal->offered);
        self::assertStringNotContainsString(self::ADDRESS, (string) json_encode($refusal->toArray()));
    }

    /**
     * Define the routes the tests call.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->middlewareGroup('gated', ['mfa']);
        $router->middlewareGroup('exempted', ['mfa.exempt']);

        $router->get(self::BARE, self::reached(...))->middleware('mfa');
        $router->get(self::LEVEL, self::reached(...))->middleware('mfa:level=aal2');
        $router->get(self::OPERATION, self::reached(...))->middleware('mfa:operation=' . self::CLOSE_BOOKS);
        $router->get(self::BOTH, self::reached(...))->middleware('mfa:level=aal2,operation=' . self::CLOSE_BOOKS);
        $router->get('gate/stacked', self::reached(...))->middleware(['mfa:operation=' . self::CLOSE_BOOKS, 'mfa:level=aal2']);
        $router->get('gate/guarded', self::reached(...))->middleware(['mfa:level=aal2', 'auth:api']);

        $router->get('gate/exempt', self::reached(...))->middleware(['mfa', 'mfa.exempt']);
        $router->get('gate/exempt-first', self::reached(...))->middleware(['mfa.exempt', 'mfa']);
        $router->get('gate/exempt-level', self::reached(...))->middleware(['mfa:level=aal2', 'mfa.exempt']);
        $router->get('gate/exempt-group-after', self::reached(...))->middleware(['gated', 'exempted']);
        $router->get('gate/exempt-group-before', self::reached(...))->middleware(['exempted', 'gated']);
        $router->get('gate/exempt-class', self::reached(...))->middleware(['mfa', ExemptFromMfa::class]);
        $router->get('gate/exempt-excluded', self::reached(...))->middleware(['mfa', 'mfa.exempt'])->withoutMiddleware('mfa.exempt');
    }

    /**
     * What a route answers when it is reached.
     *
     * @return string
     */
    private static function reached(): string
    {
        return 'reached';
    }

    /**
     * The refusal a request to the route is answered with.
     *
     * @param  string  $uri
     * @return \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     */
    private function refusal(string $uri): InsufficientAuthenticationException
    {
        $refusal = $this->get($uri)->exception;

        self::assertInstanceOf(InsufficientAuthenticationException::class, $refusal);

        return $refusal;
    }

    /**
     * Record the proofs on the person's sign-in.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  string  $session
     * @param  string  $application
     * @return void
     */
    private function prove(TestUser $user, \Closure $proofs, string $session = self::SESSION, string $application = self::APPLICATION): void
    {
        $signIn = SignInProofs::of($user)->onApplication($application)->inSession($session)->underGeneration(VerificationGeneration::current($user));

        foreach ($proofs($signIn) as $proof) {
            $this->container()->make(ProofStore::class)->record($proof);
        }
    }

    /**
     * Ask nothing of a sign-in, and configure the operation the routes name to
     * want a verification within five minutes.
     *
     * @return void
     */
    private function configureTheOperation(): void
    {
        $this->enableApplication(['requirement' => 'never', 'freshness' => [self::CLOSE_BOOKS => 300]]);
    }

    /**
     * Put a person on each of two guards, the `web` default one having met AAL2
     * unless it is the `api` one that has.
     *
     * @param  bool  $apiProved
     * @return void
     */
    private function arrangeTwoGuards(bool $apiProved): void
    {
        config()->set('auth.guards.api', ['driver' => 'session', 'provider' => 'users']);

        $web = $this->signedInPerson();
        $api = $this->person('api@example.test');

        $this->actingAs($api, 'api');

        $this->container()->make(ProofStore::class)->begin($api, 'api', 'sign-in-api');

        if ($apiProved) {
            $this->prove($api, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()], 'sign-in-api', 'api');
        } else {
            $this->prove($web, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);
        }

        Auth::shouldUse('web');
    }

    /**
     * Run the middleware directly, with no matched route, for a request the
     * container serves.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet  $instance
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException
     */
    private function handleDirectly(?EnsureMfaRequirementIsMet $instance = null): Response
    {
        $request = Request::create('/');

        $this->container()->instance('request', $request);

        return ($instance ?? $this->container()->make(EnsureMfaRequirementIsMet::class))
            ->handle($request, static fn (): Response => new Response('reached'), 'level=aal2');
    }
}
