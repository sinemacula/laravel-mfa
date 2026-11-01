<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Session\Session;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate;
use SineMacula\Laravel\Mfa\Requirements\OperationRequirements;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\RecordingCombinationPolicy;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `ConfiguredFreshnessGate`: a session is fresh for an operation only
 * when its recorded proofs meet the stricter of the application's configured
 * requirement and the caller's. An operation with neither is never fresh, nor
 * is a session with no record; a fresh weaker proof never refreshes an old
 * stronger one, a fresh first factor never stands in for an additional factor,
 * and refreshing the session renews nothing.
 *
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
     * Fix the time the tests start at.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(self::NOW);
    }

    /**
     * Release the fixed time.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An operation that neither the package nor the application names, asked
     * about with no requirement of the caller's, is never fresh, however fresh
     * the session's proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnknownOperationIsNeverFresh(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        self::assertTrue($this->gate()->isFresh('mfa.add_factor'));
        self::assertFalse($this->gate()->isFresh('billing.change_plan'));
        self::assertFalse($this->gate()->isFresh('billing.change_plan', Requirement::none()));
    }

    /**
     * A name that is not an operation's is never fresh, whatever the caller
     * asks.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANameThatIsNotAnOperationsIsNeverFresh(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(), $signIn->totp()]);

        $caller = Requirement::none()->withAdditionalVerification(900);

        self::assertTrue($this->gate()->isFresh('billing.change_plan', $caller));
        self::assertFalse($this->gate()->isFresh('Billing.Change_Plan', $caller));
        self::assertFalse($this->gate()->isFresh("billing.change_plan\n", $caller));
    }

    /**
     * The package's own operations ask for an additional verification within
     * fifteen minutes unless the application sets them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePackagesOperationsAreFreshForFifteenMinutes(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp()]);

        self::assertTrue($this->gate()->isFresh('mfa.generate_recovery_codes'));

        self::travelSeconds(900);

        self::assertTrue($this->gate()->isFresh('mfa.generate_recovery_codes'));

        self::travelSeconds(1);

        self::assertFalse($this->gate()->isFresh('mfa.generate_recovery_codes'));
    }

    /**
     * The stricter of the configured requirement and the caller's applies,
     * whichever of the two is stricter.
     *
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

        self::assertFalse($this->gate()->isFresh('mfa.remove_factor', $looser));
        self::assertTrue($this->gate()->isFresh('mfa.add_factor', $looser));
        self::assertFalse($this->gate()->isFresh('mfa.add_factor', $stricter));
        self::assertTrue($this->gate()->isFresh('reports.export', $looser));
        self::assertFalse($this->gate()->isFresh('reports.export', $stricter));
    }

    /**
     * A caller's requirement adds parts of its own: a level asked for by the
     * caller must be met as well as the configured additional verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheCallersPartsAreAddedToTheConfiguredOnes(): void
    {
        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->email()]);

        self::assertTrue($this->gate()->isFresh('mfa.add_factor'));
        self::assertFalse($this->gate()->isFresh('mfa.add_factor', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 900)));
    }

    /**
     * A fresh weaker proof never refreshes an old stronger one: an old TOTP
     * code after a password reached AAL2, and a fresh email code or password
     * reauthentication does not bring it back, though the reauthentication is
     * fresh for the AAL1 it reaches on its own.
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

        self::assertFalse($this->gate()->isFresh('billing.change_plan'));
        self::assertTrue($this->gate()->isFresh('reports.export', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, 900)));
    }

    /**
     * A fresh first factor never stands in for an additional factor: neither a
     * sign-in made now nor a reauthentication made now is fresh for an
     * operation that asks for an additional verification.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAFreshFirstFactorNeverStandsInForAnAdditionalFactor(): void
    {
        $user = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password()]);

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));

        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp(self::TWO_HOURS), $signIn->reauthentication()], $user);

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));
    }

    /**
     * Refreshing or regenerating the Laravel session renews nothing: only the
     * proofs' own times count, so the session stops being fresh once they are
     * older than the requirement allows.
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

        self::assertTrue($this->gate()->isFresh('mfa.add_factor'));

        self::travelSeconds(301);

        $session->regenerate();

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));
    }

    /**
     * A session with no record is not fresh: no identity, no sign-in the store
     * knows of, or a sign-in with no proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testASessionWithNoRecordIsNotFresh(): void
    {
        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));

        $user = TestUser::query()->create(['email' => 'none@example.test']);

        $this->actingAs($user);

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));

        $this->signIn(static fn (SignInProofs $signIn): array => [], $user);

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));
    }

    /**
     * A caller's requirement with a part that carries no maximum age is
     * refused.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnboundedCallerRequirementIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $this->gate()->isFresh('mfa.add_factor', Requirement::none()->withAdditionalVerification());
    }

    /**
     * Without a first factor in the store, the one a bound resolver reports for
     * the current sign-in counts; it is not asked when the store holds one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolvedFirstFactorCountsOnlyWhenTheStoreHoldsNone(): void
    {
        $user     = $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->totp()]);
        $resolver = new FixedFirstFactorResolver(SignInProofs::of($user)->password(self::TWO_HOURS));

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));

        $this->container()->instance(FirstFactorResolver::class, $resolver);

        self::assertTrue($this->gate()->isFresh('mfa.add_factor'));
        self::assertSame(1, $resolver->asked);

        $this->signIn(static fn (SignInProofs $signIn): array => [$signIn->password(self::TWO_HOURS), $signIn->totp()], $user);

        self::assertTrue($this->gate()->isFresh('mfa.add_factor'));
        self::assertSame(1, $resolver->asked);
    }

    /**
     * Rows of a first factor a resolver reports that may not count for the
     * current sign-in, as the sign-in's proofs would make it.
     *
     * @return iterable<string, array{\Closure(\Tests\Fixtures\Requirements\SignInProofs): ?\SineMacula\Laravel\Mfa\Proofs\Proof}>
     */
    public static function untrustedFirstFactors(): iterable
    {
        yield 'none' => [static fn (SignInProofs $signIn): ?Proof => null];
        yield 'a reauthentication' => [static fn (SignInProofs $signIn): ?Proof => $signIn->reauthentication(self::TWO_HOURS)];
        yield 'another identity\'s' => [static fn (SignInProofs $signIn): ?Proof => $signIn->ofIdentity('999')->password(self::TWO_HOURS)];
        yield 'another application\'s' => [static fn (SignInProofs $signIn): ?Proof => $signIn->onApplication('admin')->password(self::TWO_HOURS)];
        yield 'another sign-in\'s' => [static fn (SignInProofs $signIn): ?Proof => $signIn->inSession('sign-in-2')->password(self::TWO_HOURS)];
        yield 'an older generation\'s' => [static fn (SignInProofs $signIn): ?Proof => $signIn->underGeneration(1)->password(self::TWO_HOURS)];
        yield 'one made after now' => [static fn (SignInProofs $signIn): ?Proof => $signIn->password(-60)];
    }

    /**
     * A first factor a resolver reports counts for nothing unless it is a first
     * factor of the identity on the application, bound to the current sign-in,
     * made under the current generation and not after now: the combination
     * policy is handed no proof at all.
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

        self::assertFalse($this->gate()->isFresh('mfa.add_factor'));
        self::assertSame([[]], $policy->handed);
    }

    /**
     * Without a sign-in the store knows of, a resolver's first factor counts
     * for nothing.
     *
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

        self::assertFalse($this->gate()->isFresh('mfa.add_factor', Requirement::none()->withMinimumLevel(AssuranceLevel::AAL1, self::TWO_HOURS)));
        self::assertSame(0, $resolver->asked);
    }

    /**
     * The gate is the default the container binds.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testIsTheBoundGate(): void
    {
        self::assertInstanceOf(ConfiguredFreshnessGate::class, $this->container()->make(FreshnessGate::class));
    }

    /**
     * Sign the user in, a new one unless given, beginning a sign-in on the
     * default application and recording the proofs it made.
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
            $store->record($proof);
        }

        return $user;
    }

    /**
     * Move the fixed time on by the given number of seconds.
     *
     * @param  int  $seconds
     * @return void
     */
    private static function travelSeconds(int $seconds): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds($seconds));
    }

    /**
     * Resolve the gate under test.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\ConfiguredFreshnessGate
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function gate(): ConfiguredFreshnessGate
    {
        return $this->container()->make(ConfiguredFreshnessGate::class);
    }
}
