<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\OperationRequirements;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Context\InvertedActiveState;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\RecordingCombinationPolicy;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfiguredFreshnessGate::class)]
#[CoversClass(OperationRequirements::class)]
final class ConfiguredFreshnessGateTest extends TestCase
{
    use RefreshDatabase;

    /** @var string The time the tests start at. */
    private const string NOW = '2026-11-01T12:00:00.000000+00:00';

    /** @var int The age of a proof made two hours ago, in seconds. */
    private const int TWO_HOURS = 7200;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(self::NOW);
    }

    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Asked with no caller requirement, however fresh the proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnknownOperationIsNeverFresh(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'billing.change_plan'));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'billing.change_plan', Requirement::none()));
    }

    /**
     * The guard's user is not judged in its place.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPendingSessionIsNeverFresh(): void
    {
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        $proofs = SignInProofs::of($user)->inSession('pending-1');

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(new PendingContext(
            $user,
            SignInProofs::APPLICATION,
            'pending-1',
            $proofs->password(),
            Requirement::none()->withAdditionalVerification(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        )));

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertNull($this->gate()->freshUntil(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function identitiesNotServed(): iterable
    {
        yield 'a machine' => [false, true];
        yield 'an inactive identity' => [true, false];
    }

    /**
     * Neither a machine nor an inactive identity, whatever proofs the store
     * holds.
     *
     * @param  bool  $person
     * @param  bool  $active
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('identitiesNotServed')]
    public function testAnIdentityNotServedIsNeverFresh(bool $person, bool $active): void
    {
        $identity = new NonEloquentIdentity('someone-1', person: $person, active: $active);
        $signIn   = SignInProofs::of($identity);
        $store    = $this->container()->make(ProofStore::class);

        $this->actingAs($identity);

        $store->begin($identity, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record($identity, $signIn->password());
        $store->record($identity, $signIn->totp());

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertNull($this->gate()->freshUntil(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * The resolver decides, not the identity; one it finds active is judged by
     * its proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIdentityTheBoundResolverFindsInactiveIsNeverFresh(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        $this->container()->instance(ActiveStateResolver::class, new InvertedActiveState);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertNull($this->gate()->freshUntil(Callers::current(), 'mfa.add_factor'));

        $identity = new NonEloquentIdentity('someone-1', active: false);
        $signIn   = SignInProofs::of($identity);
        $store    = $this->container()->make(ProofStore::class);

        $this->actingAs($identity);

        $store->begin($identity, SignInProofs::APPLICATION, SignInProofs::SESSION);
        $store->record($identity, $signIn->password());
        $store->record($identity, $signIn->totp());

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * Never throws, even for an unbounded caller requirement.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANameThatIsNotAnOperationsIsNeverFresh(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        $caller = Requirement::none()->withAdditionalVerification(900);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'billing.change_plan', $caller));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'Billing.Change_Plan', $caller));
        self::assertFalse($this->gate()->isFresh(Callers::current(), "billing.change_plan\n", $caller));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'Billing.Change_Plan', Requirement::none()->withMultifactor()));
    }

    /**
     * An additional verification within fifteen minutes, unless the application
     * configures them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePackagesOperationsAreFreshForFifteenMinutes(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp()]);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.generate_recovery_codes'));

        self::travelSeconds(900);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.generate_recovery_codes'));

        self::travelSeconds(1);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.generate_recovery_codes'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheStricterSettingAppliesBothWays(): void
    {
        config()->set('mfa.applications.web.freshness', ['mfa.remove_factor' => 300]);

        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp(400)]);

        $looser   = Requirement::none()->withAdditionalVerification(600);
        $stricter = Requirement::none()->withAdditionalVerification(60);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.remove_factor', $looser));
        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor', $looser));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor', $stricter));
        self::assertTrue($this->gate()->isFresh(Callers::current(), 'reports.export', $looser));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'reports.export', $stricter));
    }

    /**
     * A level the caller asks for must be met as well as the configured
     * additional verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheCallersPartsAreAddedToTheConfiguredOnes(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->email()]);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 900)));
    }

    /**
     * An old TOTP code reached AAL2; a fresh email code or reauthentication
     * does not restore it, though the reauthentication is fresh for AAL1.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFreshWeakerProofNeverRefreshesAnOldStrongerOne(): void
    {
        config()->set('mfa.applications.web.freshness', ['billing.change_plan' => ['minimum_level' => ['level' => 'aal2', 'max_age' => 900]]]);

        $this->signIn(static fn (SignInProofs $signIn): array => [
            $signIn->password(self::TWO_HOURS),
            $signIn->totp(self::TWO_HOURS),
            $signIn->email(),
            $signIn->reauthentication(),
        ]);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'billing.change_plan'));
        self::assertTrue($this->gate()->isFresh(Callers::current(), 'reports.export', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, 900)));
    }

    /**
     * Neither a sign-in nor a reauthentication made now meets an additional
     * verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFreshFirstFactorNeverStandsInForAnAdditionalFactor(): void
    {
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password()]);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp(self::TWO_HOURS), $signIn->reauthentication()], $user);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * Only the proofs' own times count.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshingTheSessionNeverRenewsFreshness(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        $session = $this->container()->make(Session::class);

        self::travelSeconds(600);

        $session->regenerate();
        $session->migrate(true);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        self::travelSeconds(301);

        $session->regenerate();

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * No identity, no sign-in the store knows of, or a sign-in with no proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASessionWithNoRecordIsNotFresh(): void
    {
        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        $user = TestUser::query()->create(['email' => 'none@example.test']);

        $this->actingAs($user);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        $this->signIn(static fn (SignInProofs $signIn): array => [], $user);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnboundedCallerRequirementIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->gate()->isFresh(Callers::current(), 'mfa.add_factor', Requirement::none()->withAdditionalVerification());
    }

    /**
     * The resolver is not asked when the store holds one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedFirstFactorCountsOnlyWhenTheStoreHoldsNone(): void
    {
        $user     = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->totp()]);
        $resolver = new FixedFirstFactorResolver(SignInProofs::of($user)->password(self::TWO_HOURS));

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));

        $this->container()->instance(FirstFactorResolver::class, $resolver);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertSame(1, $resolver->asked);

        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp()], $user);

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertSame(1, $resolver->asked);
    }

    /**
     * Not only the oldest, so a fresh factor recorded after a stale one still
     * counts.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedFirstFactorIsJudgedWithEveryRecordedProof(): void
    {
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->email(self::TWO_HOURS), $signIn->totp()]);

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(SignInProofs::of($user)->password(self::TWO_HOURS)));

        self::assertTrue($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
    }

    /**
     * @return iterable<string, array{\Closure(\Tests\Fixtures\Requirements\SignInProofs): ?\SineMacula\Laravel\Mfa\Proofs\Proof}>
     */
    public static function untrustedFirstFactors(): iterable
    {
        yield 'none' => [static fn (SignInProofs $signIn): ?Proof => null];
        yield 'a reauthentication' => [static fn (SignInProofs $signIn): Proof => $signIn->reauthentication(self::TWO_HOURS)];
        yield 'another identity\'s' => [static fn (SignInProofs $signIn): Proof => $signIn->ofIdentity('999')->password(self::TWO_HOURS)];
        yield 'another application\'s' => [static fn (SignInProofs $signIn): Proof => $signIn->onApplication('admin')->password(self::TWO_HOURS)];
        yield 'another sign-in\'s' => [static fn (SignInProofs $signIn): Proof => $signIn->inSession('sign-in-2')->password(self::TWO_HOURS)];
        yield 'an older generation\'s' => [static fn (SignInProofs $signIn): Proof => $signIn->underGeneration(1)->password(self::TWO_HOURS)];
        yield 'one made after now' => [static fn (SignInProofs $signIn): Proof => $signIn->password(-60)];
    }

    /**
     * It must be the identity's first factor on the application, bound to the
     * current sign-in, made under the current generation and not after now.
     *
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): ?\SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('untrustedFirstFactors')]
    public function testAnUntrustedResolvedFirstFactorCountsForNothing(\Closure $firstFactor): void
    {
        $user   = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->totp()]);
        $policy = new RecordingCombinationPolicy;

        $this->container()->instance(CombinationPolicy::class, $policy);
        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver($firstFactor(SignInProofs::of($user))));

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor'));
        self::assertSame([[]], $policy->handed);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedFirstFactorNeedsASignIn(): void
    {
        $user     = TestUser::query()->create(['email' => 'resolved@example.test']);
        $resolver = new FixedFirstFactorResolver(SignInProofs::of($user)->password(self::TWO_HOURS));

        $this->actingAs($user);
        $this->container()->instance(FirstFactorResolver::class, $resolver);

        self::assertFalse($this->gate()->isFresh(Callers::current(), 'mfa.add_factor', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, self::TWO_HOURS)));
        self::assertSame(0, $resolver->asked);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsTheBoundGate(): void
    {
        self::assertInstanceOf(ConfiguredFreshnessGate::class, $this->container()->make(FreshnessGate::class));
    }

    /**
     * A new user unless given; begins a sign-in on the default application and
     * records its proofs.
     *
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  ?\Tests\Fixtures\Identities\TestUser  $user
     * @return \Tests\Fixtures\Identities\TestUser
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signIn(\Closure $proofs, ?TestUser $user = null): TestUser
    {
        $user ??= TestUser::query()->create(['email' => 'fresh@example.test']);

        $this->actingAs($user);

        $store = $this->container()->make(ProofStore::class);

        $store->begin($user, SignInProofs::APPLICATION, SignInProofs::SESSION);

        foreach ($proofs(SignInProofs::of($user)) as $proof) {
            $store->record($user, $proof);
        }

        return $user;
    }

    /**
     * @param  int  $seconds
     * @return void
     */
    private static function travelSeconds(int $seconds): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds($seconds));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gate(): ConfiguredFreshnessGate
    {
        return $this->container()->make(ConfiguredFreshnessGate::class);
    }
}
