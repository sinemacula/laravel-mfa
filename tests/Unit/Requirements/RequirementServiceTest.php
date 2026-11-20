<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\ActiveTenantResolver;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoActiveTenant;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedActiveTenant;
use Tests\Fixtures\Requirements\FixedTenantRequirement;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementService::class)]
#[CoversClass(ReenrollmentObligation::class)]
#[CoversClass(IdentityContractRequirement::class)]
#[CoversClass(NoTenantRequirement::class)]
final class RequirementServiceTest extends TestCase
{
    use RefreshDatabase;

    /** @var string The application the sign-ins are on. */
    private const string APPLICATION = 'web';

    /** @var string The tenant a sign-in may be active in. */
    private const string TENANT = 'tenant-1';

    /** @var string The identity's key. */
    private const string IDENTITY = 'plain-1';

    /**
     * Mode (null when unconfigured), confirmed factor, own requirement, obliged
     * to enrol again, tenant active, and the serialised requirement.
     *
     * @return iterable<string, array{?string, bool, bool, bool, bool, array<string, array<string, int|string|null>>}>
     */
    public static function compositions(): iterable
    {
        $modes = [
            'never'                              => ['never', true, false],
            'an application nobody configured'   => [null, true, false],
            'enrolled, with no confirmed factor' => ['enrolled', false, false],
            'enrolled, with a confirmed factor'  => ['enrolled', true, true],
            'always'                             => ['always', false, true],
        ];

        foreach ($modes as $label => [$mode, $enabled, $applicationRequires]) {
            foreach (self::switches() as [$own, $obliged, $tenant]) {
                $name = self::rowName($label, $own, $obliged, $tenant);

                yield $name => [$mode, $enabled, $own, $obliged, $tenant, self::expected($applicationRequires || $obliged, $own, $tenant)];
            }
        }
    }

    /**
     * @param  ?string  $mode
     * @param  bool  $enabled
     * @param  bool  $own
     * @param  bool  $obliged
     * @param  bool  $tenant
     * @param  array<string, array<string, int|string|null>>  $expected
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('compositions')]
    public function testComposesTheStrictestOfEveryPart(?string $mode, bool $enabled, bool $own, bool $obliged, bool $tenant, array $expected): void
    {
        if ($mode !== null) {
            config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => $mode]);
        }

        $this->container()->instance(TenantRequirement::class, new FixedTenantRequirement(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)));

        $identity = new NonEloquentIdentity(self::IDENTITY, mfaEnabled: $enabled, requirement: $own ? self::identityRequirement() : null);

        if ($obliged) {
            self::oblige(NonEloquentIdentity::class, self::IDENTITY);
        }

        $this->activate($tenant ? self::TENANT : null);

        $requirement = $this->service()->requirementFor($identity, self::APPLICATION);

        self::assertSame($expected, $requirement->toArray());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheIdentitysRequirementLeavesOutTheActiveTenants(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => 'always']);

        $this->container()->instance(TenantRequirement::class, new FixedTenantRequirement(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)));
        $this->activate(self::TENANT);

        $identity = new NonEloquentIdentity(self::IDENTITY);

        self::assertSame(['additional_verification' => ['max_age' => null]], $this->service()->identityRequirementFor($identity, self::APPLICATION)->toArray());
    }

    /**
     * So the order the sources are asked in never changes the answer.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePartsComposeAlikeInAnyOrder(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => 'always']);

        $tenant = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 300);

        $this->container()->instance(TenantRequirement::class, new FixedTenantRequirement($tenant));

        self::oblige(NonEloquentIdentity::class, self::IDENTITY);

        $identity = new NonEloquentIdentity(self::IDENTITY, requirement: self::identityRequirement());

        $this->activate(self::TENANT);

        $composed = $this->service()->requirementFor($identity, self::APPLICATION)->toArray();
        $parts    = [Requirement::none()->withAdditionalVerification(), self::identityRequirement(), Requirement::none()->withAdditionalVerification(), $tenant];

        foreach (self::permutations($parts) as $order) {
            self::assertSame($composed, Requirement::strictest(...$order)->toArray());
        }
    }

    /**
     * With the identity, application and tenant, and only when the bound
     * resolver names one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAsksTheTenantOnlyWhenOneIsActive(): void
    {
        $identity = new NonEloquentIdentity(self::IDENTITY);

        self::assertInstanceOf(NoActiveTenant::class, $this->container()->make(ActiveTenantResolver::class));
        self::assertInstanceOf(NoTenantRequirement::class, $this->container()->make(TenantRequirement::class));

        $this->activate(self::TENANT);

        self::assertTrue($this->service()->requirementFor($identity, self::APPLICATION)->isEmpty());

        $tenants = \Mockery::mock(TenantRequirement::class);
        $tenants->shouldReceive('requirementFor')->once()->with($identity, self::APPLICATION, self::TENANT)->andReturn(Requirement::none()->withMultifactor());

        $this->container()->instance(TenantRequirement::class, $tenants);

        $this->activate(null);

        self::assertTrue($this->service()->requirementFor($identity, self::APPLICATION)->isEmpty());

        $this->activate(self::TENANT);

        self::assertSame(['multifactor' => ['max_age' => null]], $this->service()->requirementFor($identity, self::APPLICATION)->toArray());
    }

    /**
     * With the identity and the application.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAsksTheBoundIdentityRequirement(): void
    {
        $identity = new NonEloquentIdentity(self::IDENTITY);

        self::assertInstanceOf(IdentityContractRequirement::class, $this->container()->make(IdentityRequirement::class));

        $seam = \Mockery::mock(IdentityRequirement::class);
        $seam->shouldReceive('requirementFor')->once()->with($identity, self::APPLICATION)->andReturn(Requirement::none()->withPhishingResistance());

        $this->container()->instance(IdentityRequirement::class, $seam);

        self::assertSame(['phishing_resistance' => ['max_age' => null]], $this->service()->requirementFor($identity, self::APPLICATION)->toArray());
    }

    /**
     * Another identity's, one of another type with the same key, or a cleared
     * one obliges nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheObligationIsTheIdentitysOwn(): void
    {
        self::oblige(NonEloquentIdentity::class, 'plain-2');
        self::oblige(TestUser::class, self::IDENTITY);
        self::oblige(NonEloquentIdentity::class, 'plain-3', false);

        self::assertFalse(ReenrollmentObligation::isRequired(new NonEloquentIdentity(self::IDENTITY)));
        self::assertFalse(ReenrollmentObligation::isRequired(new NonEloquentIdentity('plain-3')));
        self::assertTrue(ReenrollmentObligation::isRequired(new NonEloquentIdentity('plain-2')));
        self::assertTrue($this->service()->requirementFor(new NonEloquentIdentity(self::IDENTITY), self::APPLICATION)->isEmpty());
    }

    /**
     * Configured or not.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheObligationAppliesInEveryApplication(): void
    {
        config()->set('mfa.applications.admin', ['requirement' => 'never']);

        self::oblige(NonEloquentIdentity::class, self::IDENTITY);

        $identity = new NonEloquentIdentity(self::IDENTITY);

        foreach (['web', 'admin', 'mobile'] as $application) {
            self::assertSame(['additional_verification' => ['max_age' => null]], $this->service()->requirementFor($identity, $application)->toArray());
        }
    }

    /**
     * Composed on the current application; without an MFA-capable identity it
     * asks for nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRequirementIsTheCallers(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => 'always']);

        self::assertTrue($this->service()->requirement(Callers::current())->isEmpty());

        $this->actingAs(new PlainUser);

        self::assertTrue($this->service()->requirement(Callers::current())->isEmpty());

        $this->actingAs(TestUser::query()->create(['email' => 'current@example.test', 'mfa_enabled' => false]));

        self::assertSame(['additional_verification' => ['max_age' => null]], $this->service()->requirement(Callers::current())->toArray());
    }

    /**
     * The guard's user with a pending session asks for nothing, whatever the
     * application's mode; its requirement is the pending session's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPendingCallersRequirementIsEmpty(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => 'always']);

        $user    = TestUser::query()->create(['email' => 'pending@example.test', 'mfa_enabled' => true]);
        $signIn  = SignInProofs::of($user)->inSession('pending-1');
        $pending = new PendingContext(
            $user,
            self::APPLICATION,
            'pending-1',
            $signIn->password(),
            Requirement::none()->withAdditionalVerification(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        );

        $this->actingAs($user);
        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($pending));

        self::assertTrue($this->service()->requirement(CallerContext::forPending($pending))->isEmpty());
        self::assertTrue($this->service()->requirement(Callers::current())->isEmpty());
        self::assertSame(['additional_verification' => ['max_age' => null]], $this->service()->requirement(CallerContext::forIdentity($user, self::APPLICATION))->toArray());
    }

    /**
     * Each read from the caller's own application, for the same identity.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheRequirementAndFreshnessFollowTheCallersApplication(): void
    {
        config()->set('mfa.applications.web', ['requirement' => 'never', 'freshness' => ['billing.close' => 60]]);
        config()->set('mfa.applications.admin', ['requirement' => 'always', 'freshness' => ['billing.close' => 900]]);

        $user  = TestUser::query()->create(['email' => 'applications@example.test', 'mfa_enabled' => false]);
        $store = $this->container()->make(ProofStore::class);

        foreach (['web', 'admin'] as $application) {
            $signIn = SignInProofs::of($user)->onApplication($application)->inSession($application . '-sign-in');

            $store->begin($user, $application, $signIn->sessionId);
            $store->record($user, $signIn->password(3600));
            $store->record($user, $signIn->totp(300));
        }

        $web   = CallerContext::forIdentity($user, 'web');
        $admin = CallerContext::forIdentity($user, 'admin');

        self::assertTrue($this->service()->requirement($web)->isEmpty());
        self::assertSame(['additional_verification' => ['max_age' => null]], $this->service()->requirement($admin)->toArray());
        self::assertFalse($this->service()->isFresh($web, 'billing.close'));
        self::assertTrue($this->service()->isFresh($admin, 'billing.close'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testFreshnessReadsOnlyTheCallersApplicationsProofs(): void
    {
        config()->set('mfa.applications.web', ['freshness' => ['billing.close' => 900]]);
        config()->set('mfa.applications.admin', ['freshness' => ['billing.close' => 900]]);

        $user  = TestUser::query()->create(['email' => 'proofs@example.test', 'mfa_enabled' => true]);
        $store = $this->container()->make(ProofStore::class);

        foreach (['web' => 300, 'admin' => 3600] as $application => $factorAge) {
            $signIn = SignInProofs::of($user)->onApplication($application)->inSession($application . '-sign-in');

            $store->begin($user, $application, $signIn->sessionId);
            $store->record($user, $signIn->password(3600));
            $store->record($user, $signIn->totp($factorAge));
        }

        self::assertTrue($this->service()->isFresh(CallerContext::forIdentity($user, 'web'), 'billing.close'));
        self::assertFalse($this->service()->isFresh(CallerContext::forIdentity($user, 'admin'), 'billing.close'));
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function modes(): iterable
    {
        yield 'never' => ['never'];
        yield 'enrolled' => ['enrolled'];
        yield 'always' => ['always'];
        yield 'an application nobody configured' => [null];
    }

    /**
     * Its obligation cannot be read, so it is refused rather than answered as
     * empty, under every mode.
     *
     * @param  ?string  $mode
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('modes')]
    public function testANonScalarIdentifiersRequirementIsRefused(?string $mode): void
    {
        if ($mode !== null) {
            config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => $mode]);
        }

        $identity = new NonScalarIdentifierUser;

        try {
            $this->service()->requirementFor($identity, self::APPLICATION);
            self::fail('Expected the identity\'s requirement to be refused.');
        } catch (UnsupportedIdentifierException) {
            // Refused, as expected.
        }

        $this->actingAs($identity);

        $this->expectException(UnsupportedIdentifierException::class);

        $this->service()->requirement(Callers::current());
    }

    /**
     * The package's setting for the operation, made stricter by the one given;
     * an operation the package does not name passes only the one given.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAsksTheGateWithThePackagesSetting(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['freshness' => ['mfa.remove_factor' => 300]]);

        $extra = Requirement::none()->withAdditionalVerification(600)->withMinimumLevel(AssuranceLevel::AAL2, 60);
        $asked = [];

        $this->container()->instance(FreshnessGate::class, self::gateRecording($asked, true));

        self::assertTrue($this->service()->isFresh(Callers::current(), 'mfa.remove_factor'));
        self::assertTrue($this->service()->isFresh(Callers::current(), 'mfa.remove_factor', $extra));
        self::assertTrue($this->service()->isFresh(Callers::current(), 'billing.change_plan', $extra));
        self::assertTrue($this->service()->isFresh(Callers::current(), 'billing.change_plan', Requirement::none()));
        self::assertTrue($this->service()->isFresh(Callers::current(), 'billing.change_plan'));

        self::assertSame([
            ['mfa.remove_factor', ['additional_verification' => ['max_age' => 300]]],
            ['mfa.remove_factor', ['additional_verification' => ['max_age' => 300], 'minimum_level' => ['level' => 'aal2', 'max_age' => 60]]],
            ['billing.change_plan', ['additional_verification' => ['max_age' => 600], 'minimum_level' => ['level' => 'aal2', 'max_age' => 60]]],
            ['billing.change_plan', null],
            ['billing.change_plan', null],
        ], $asked);
    }

    /**
     * Whatever the gate or the caller would say, so it never throws; the gate
     * is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANameThatIsNotAnOperationsIsNeverFresh(): void
    {
        $asked = [];

        $this->container()->instance(FreshnessGate::class, self::gateRecording($asked, true));

        self::assertFalse($this->service()->isFresh(Callers::current(), 'Mfa.Add_Factor', Requirement::none()->withAdditionalVerification(60)));
        self::assertFalse($this->service()->isFresh(Callers::current(), "mfa.add_factor\n"));
        self::assertFalse($this->service()->isFresh(Callers::current(), 'Not An Operation', Requirement::none()->withMultifactor()));
        self::assertSame([], $asked);
    }

    /**
     * Whatever the caller would say, so it never throws; the gate is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANameThatIsNotAnOperationsHasNoFreshnessRequirement(): void
    {
        $asked = [];

        $this->container()->instance(FreshnessGate::class, self::gateRecording($asked, true));

        self::assertNull($this->service()->freshnessRequirement(Callers::current(), 'Not An Operation', Requirement::none()->withMultifactor()));
        self::assertNotNull($this->service()->freshnessRequirement(Callers::current(), 'billing.change_plan', Requirement::none()->withAdditionalVerification(600)));
        self::assertSame([['billing.change_plan', ['additional_verification' => ['max_age' => 600]]]], $asked);
    }

    /**
     * Before the gate is asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUnboundedCallerRequirementIsRefused(): void
    {
        $asked = [];

        $this->container()->instance(FreshnessGate::class, self::gateRecording($asked, true));

        try {
            $this->service()->isFresh(Callers::current(), 'mfa.add_factor', Requirement::none()->withAdditionalVerification());
            self::fail('Expected the caller\'s requirement to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $expected = 'A caller\'s requirement must give every part a max_age from 1 to 86400 seconds, which its [additional_verification] part does not.';

            self::assertSame($expected, $exception->getMessage());
        }

        self::assertSame([], $asked);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    private static function identityRequirement(): Requirement
    {
        return Requirement::none()->withAdditionalVerification(600)->withMultifactor(600);
    }

    /**
     * Own requirement, obliged to enrol again, tenant active.
     *
     * @return list<array{bool, bool, bool}>
     */
    private static function switches(): array
    {
        return [
            [false, false, false],
            [false, false, true],
            [false, true, false],
            [false, true, true],
            [true, false, false],
            [true, false, true],
            [true, true, false],
            [true, true, true],
        ];
    }

    /**
     * @param  string  $label
     * @param  bool  $own
     * @param  bool  $obliged
     * @param  bool  $tenant
     * @return string
     */
    private static function rowName(string $label, bool $own, bool $obliged, bool $tenant): string
    {
        return sprintf(
            '%s, %s, %s, %s',
            $label,
            $own ? 'an identity requirement' : 'no identity requirement',
            $obliged ? 'obliged to enrol again' : 'no obligation',
            $tenant ? 'a tenant' : 'no tenant',
        );
    }

    /**
     * @param  bool  $additional
     * @param  bool  $own
     * @param  bool  $tenant
     * @return array<string, array<string, int|string|null>>
     */
    private static function expected(bool $additional, bool $own, bool $tenant): array
    {
        $expected = [];

        if ($own) {
            $expected['additional_verification'] = ['max_age' => 600];
            $expected['multifactor']             = ['max_age' => 600];
        } elseif ($additional) {
            $expected['additional_verification'] = ['max_age' => null];
        }

        if ($tenant) {
            $expected['minimum_level'] = ['level' => 'aal2', 'max_age' => null];
        }

        return $expected;
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Requirements\Requirement>  $parts
     * @return list<list<\SineMacula\Laravel\Mfa\Requirements\Requirement>>
     */
    private static function permutations(array $parts): array
    {
        if (count($parts) <= 1) {
            return [$parts];
        }

        $orders = [];

        foreach (array_keys($parts) as $index) {
            $rest = $parts;
            $head = $rest[$index];

            unset($rest[$index]);

            foreach (self::permutations(array_values($rest)) as $tail) {
                $orders[] = [$head, ...$tail];
            }
        }

        return $orders;
    }

    /**
     * @param  string  $type
     * @param  string  $key
     * @param  bool  $required
     * @return void
     */
    private static function oblige(string $type, string $key, bool $required = true): void
    {
        $now = CarbonImmutable::now();

        DB::table('mfa_identity_states')->insert([
            'id'                    => Str::lower((string) Str::ulid()),
            'authenticatable_type'  => $type,
            'authenticatable_id'    => $key,
            'owner_hash'            => (new ProofOwner($type, $key))->hash(),
            'reenrollment_required' => $required,
            'created_at'            => $now,
            'updated_at'            => $now,
        ]);
    }

    /**
     * Records each operation and serialised caller requirement it is asked
     * with.
     *
     * @param  list<array{string, ?array<string, array<string, int|string|null>>}>  $asked
     * @param  bool  $answer
     * @return \SineMacula\Laravel\Mfa\Contracts\FreshnessGate
     */
    private static function gateRecording(array &$asked, bool $answer): FreshnessGate
    {
        $record = static function (string $operation, ?Requirement $requirement) use (&$asked): void {
            $asked[] = [$operation, $requirement?->toArray()];
        };

        return new readonly class ($record, $answer) implements FreshnessGate {
            /**
             * @param  \Closure(string, ?\SineMacula\Laravel\Mfa\Requirements\Requirement): void  $record
             * @param  bool  $answer
             */
            public function __construct(

                /** Records each question. */
                private \Closure $record,

                /** The answer to every question. */
                private bool $answer,
            ) {}

            /**
             * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
             * @param  string  $operation
             * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
             * @return bool
             */
            #[\Override]
            public function isFresh(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): bool
            {
                ($this->record)($operation, $callerRequirement);

                return $this->answer;
            }

            /**
             * The caller's requirement, unchanged.
             *
             * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
             * @param  string  $operation
             * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
             * @return ?\SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirement(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?Requirement
            {
                ($this->record)($operation, $callerRequirement);

                return $callerRequirement;
            }

            /**
             * Answers with the end of the next minute.
             *
             * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
             * @param  string  $operation
             * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
             * @return ?\Carbon\CarbonImmutable
             */
            #[\Override]
            public function freshUntil(CallerContext $caller, string $operation, ?Requirement $callerRequirement = null): ?CarbonImmutable
            {
                ($this->record)($operation, $callerRequirement);

                return $this->answer ? CarbonImmutable::now()->addMinute() : null;
            }
        };
    }

    /**
     * @param  ?string  $tenant
     * @return void
     */
    private function activate(?string $tenant): void
    {
        $this->container()->instance(ActiveTenantResolver::class, new FixedActiveTenant($tenant));
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Requirements\RequirementService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): RequirementService
    {
        return $this->container()->make(RequirementService::class);
    }
}
