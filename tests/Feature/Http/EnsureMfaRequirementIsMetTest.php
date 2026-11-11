<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
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
use Tests\Fixtures\Context\InvertedActiveState;
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
 * The `mfa` route middleware through the HTTP kernel.
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

    /** @var string Shipped English refusal message. */
    private const string REFUSAL = 'Further authentication is required.';

    /** @var string Route asking only for the composed requirement. */
    private const string BARE = 'gate/bare';

    /** @var string Route asking for AAL2. */
    private const string LEVEL = 'gate/level';

    /** @var string Route asking for the operation's freshness. */
    private const string OPERATION = 'gate/operation';

    /** @var string Route asking for AAL2 and the operation. */
    private const string BOTH = 'gate/both';

    /** @var string */
    private const string CLOSE_BOOKS = 'billing.close_books';

    /** @var array<string, array<string, ?string>> AAL2 at any age, serialised. */
    private const array AAL2 = ['minimum_level' => ['level' => 'aal2', 'max_age' => null]];

    /** @var array<string, array<string, ?int>> Additional verification at any age, serialised. */
    private const array VERIFIED = ['additional_verification' => ['max_age' => null]];

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     */
    public function testTheNeverModeAddsNothing(): void
    {
        $this->enableApplication(['requirement' => 'never']);

        $this->signedInPerson();

        $this->get(self::BARE)->assertOk();
    }

    /**
     * So a shared route group does not lock out people using optional MFA.
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
     * Refused on every `mfa` route, also under `never`.
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
     * @return void
     */
    public function testAPasswordAndTotpPassTheLevel(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp()]);

        $this->get(self::LEVEL)->assertOk();
    }

    /**
     * An email code is accepted but does not reach AAL2.
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
     * Applies where a maximum age bounds the level.
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
     * A passkey that observed user verification is multi-factor on its own.
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
     * A further proof means nothing without the first factor it follows.
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
     * The proofs cannot be tied to one sign-in.
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
     * @return void
     */
    public function testAFutureDatedProofDoesNotCount(): void
    {
        $user = $this->signedInPerson();

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60), $signIn->totp(-60)]);

        self::assertSame(self::AAL2, $this->refusal(self::LEVEL)->requirement->toArray());
    }

    /**
     * Past the maximum age the exception names the operation.
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
     * An operation with no requirement is never fresh, not misconfigured.
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
     * The gate decides an operation the local configuration does not name.
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
     * The gate's own requirement goes on the exception.
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
     * The exception carries the stricter of the two.
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
     * A proof that makes both then passes.
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
     * As from a group and a route.
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
     * @return iterable<string, array{0: \Closure(): ?\Illuminate\Contracts\Auth\Authenticatable, 1: bool}>
     */
    public static function unservedCallers(): iterable
    {
        yield 'a guest' => [static fn (): ?Authenticatable => null, false];
        yield 'a machine' => [static fn (): Authenticatable => new NonEloquentIdentity('robot-1', mfaEnabled: true, person: false), false];
        yield 'an identity that is not MFA-capable' => [static fn (): Authenticatable => PlainUser::query()->create(['email' => 'plain@example.test']), false];
    }

    /**
     * `never` sets the requirement, not who is served, so it refuses these too.
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
     * Under `never` the operation is read but no gate judged. With no stored
     * factor it reports none, whatever `isMfaEnabled()` answers.
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
        self::assertFalse($bare->hasConfirmedFactor);
        self::assertSame([], $bare->offered);
        self::assertSame(['additional_verification' => ['max_age' => 300]], $operation->requirement->toArray());
    }

    /**
     * The bound active state resolver decides, not the identity.
     *
     * @return void
     */
    public function testAnIdentityTheBoundResolverFindsInactiveIsRefused(): void
    {
        $this->configureTheOperation();

        $this->container()->instance(ActiveStateResolver::class, new InvertedActiveState);

        $this->signedInPerson();

        $bare = $this->refusal(self::BARE);

        self::assertSame([], $bare->requirement->toArray());
        self::assertFalse($bare->hasConfirmedFactor);
        self::assertSame([], $bare->offered);

        $this->actingAs(new NonEloquentIdentity('person-1', mfaEnabled: true, active: false));

        $this->get(self::BARE)->assertOk();
    }

    /**
     * It carries what it owes and any route level; no gate is asked.
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
     * Having no factor is still reported.
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
     * Also when the guard's user has met everything.
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
     * Refused at once, also on an exempt route, so a typo is loud.
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
     * At every level, in either order.
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
     * In any form, for a person who has proved nothing and for a guest.
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
     * @return void
     */
    public function testTheMarkerTakenOffIsNotAnExemption(): void
    {
        $this->enableApplication(['requirement' => 'always']);

        $this->signedInPerson();

        self::assertSame(self::VERIFIED, $this->refusal('gate/exempt-excluded')->requirement->toArray());
    }

    /**
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
     * So the middleware does not belong in the global stack.
     *
     * @return void
     */
    public function testNoMatchedRouteIsNotExempt(): void
    {
        $this->expectException(InsufficientAuthenticationException::class);

        $this->handleDirectly();
    }

    /**
     * `['mfa', 'auth:api']` authenticates first in either order.
     *
     * @return void
     */
    public function testTheIdentityOfTheNamedGuardIsJudgedWhenItIsMet(): void
    {
        $this->arrangeTwoGuards(apiProved: true);

        $this->get('gate/guarded')->assertOk();
    }

    /**
     * The default guard's identity has met everything.
     *
     * @return void
     */
    public function testTheIdentityOfTheNamedGuardIsJudgedWhenItFallsShort(): void
    {
        $this->arrangeTwoGuards(apiProved: false);

        self::assertSame(self::AAL2, $this->refusal('gate/guarded')->requirement->toArray());
    }

    /**
     * A shortfall makes no transition, so a GET never changes a session.
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
        self::assertSame([], $transition->changes);
    }

    /**
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
     * It sends no challenge header either.
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
        $response->assertExactJson(['message' => self::REFUSAL]);
        $response->assertHeaderMissing('WWW-Authenticate');
    }

    /**
     * An application renderable gives the RFC 9470 answer with factors masked.
     *
     * @return void
     */
    public function testAnApplicationCanAnswerAsTheRfcDescribes(): void
    {
        $user = $this->signedInPerson();

        $this->emailFactor($user);

        $this->prove($user, static fn (SignInProofs $signIn): array => [$signIn->password(60)]);

        $refusal = $this->refusal(self::LEVEL);

        self::assertSame('Bearer error="insufficient_user_authentication", error_description="' . self::REFUSAL . '", acr_values="aal2"', $refusal->wwwAuthenticate());

        self::assertCount(1, $refusal->offered);
        self::assertStringNotContainsString(self::ADDRESS, (string) json_encode($refusal->toArray()));
    }

    /**
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
     * @return string
     */
    private static function reached(): string
    {
        return 'reached';
    }

    /**
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
     * Records the proofs on the person's sign-in.
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
            $this->container()->make(ProofStore::class)->record($user, $proof);
        }
    }

    /**
     * Asks nothing of a sign-in, and five-minute freshness for the operation.
     *
     * @return void
     */
    private function configureTheOperation(): void
    {
        $this->enableApplication(['requirement' => 'never', 'freshness' => [self::CLOSE_BOOKS => 300]]);
    }

    /**
     * The `web` user meets AAL2, or the `api` one does when `$apiProved`.
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
     * Runs the middleware with no matched route.
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
