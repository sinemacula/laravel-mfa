<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\IdentityRequirement;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\TenantRequirement;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Requirements\IdentityContractRequirement;
use SineMacula\Laravel\Mfa\Requirements\NoTenantRequirement;
use SineMacula\Laravel\Mfa\Requirements\ReenrollmentObligation;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Requirements\RequirementService;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `RequirementService`: the composition table of a sign-in's
 * requirement (every application mode, crossed with the identity's own
 * requirement, its re-enrolment obligation and an active tenant's requirement),
 * the requirement of the current identity, and the step-up freshness asked of
 * the bound gate with this package's own setting.
 *
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
     * Every row of the composition table: the application's mode (or none for
     * an application nobody configured) and whether the identity has a
     * confirmed factor, whether it requires something of its own, whether it is
     * obliged to enrol again, whether a tenant requiring a level is active, and
     * the composed requirement, serialised.
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
     * The requirement is the strictest of the parts that apply, for every row
     * of the table.
     *
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

        $this->container()->instance(TenantRequirement::class, self::tenantRequiring(Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2)));

        $identity = new NonEloquentIdentity(self::IDENTITY, mfaEnabled: $enabled, requirement: $own ? self::identityRequirement() : null);

        if ($obliged) {
            self::oblige(NonEloquentIdentity::class, self::IDENTITY);
        }

        $requirement = $this->service()->requirementFor($identity, self::APPLICATION, $tenant ? self::TENANT : null);

        self::assertSame($expected, $requirement->toArray());
    }

    /**
     * The composed requirement is the strictest of its parts taken in any
     * order, so the order the sources are asked in never changes the answer.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePartsComposeAlikeInAnyOrder(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => 'always']);

        $tenant = Requirement::none()->withMinimumLevel(AssuranceLevel::AAL2, 300);

        $this->container()->instance(TenantRequirement::class, self::tenantRequiring($tenant));

        self::oblige(NonEloquentIdentity::class, self::IDENTITY);

        $identity = new NonEloquentIdentity(self::IDENTITY, requirement: self::identityRequirement());
        $composed = $this->service()->requirementFor($identity, self::APPLICATION, self::TENANT)->toArray();
        $parts    = [Requirement::none()->withAdditionalVerification(), self::identityRequirement(), Requirement::none()->withAdditionalVerification(), $tenant];

        foreach (self::permutations($parts) as $order) {
            self::assertSame($composed, Requirement::strictest(...$order)->toArray());
        }
    }

    /**
     * The tenant's requirement is asked with the identity, the application and
     * the tenant, and only when a tenant is active; the default tenant
     * requirement asks for nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAsksTheTenantOnlyWhenOneIsActive(): void
    {
        $identity = new NonEloquentIdentity(self::IDENTITY);

        self::assertInstanceOf(NoTenantRequirement::class, $this->container()->make(TenantRequirement::class));
        self::assertTrue($this->service()->requirementFor($identity, self::APPLICATION, self::TENANT)->isEmpty());

        $tenants = \Mockery::mock(TenantRequirement::class);
        $tenants->shouldReceive('requirementFor')->once()->with($identity, self::APPLICATION, self::TENANT)->andReturn(Requirement::none()->withMultifactor());

        $this->container()->instance(TenantRequirement::class, $tenants);

        self::assertTrue($this->service()->requirementFor($identity, self::APPLICATION)->isEmpty());
        self::assertSame(['multifactor' => ['max_age' => null]], $this->service()->requirementFor($identity, self::APPLICATION, self::TENANT)->toArray());
    }

    /**
     * The identity's own requirement is asked of the bound seam, with the
     * identity and the application.
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
     * The obligation is the identity's own: another identity's, or one of
     * another type with the same key, obliges nothing, and a cleared one
     * obliges nothing either.
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
     * The obligation applies in every application, configured or not.
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
     * The current identity's requirement is composed on the current
     * application; without an MFA-capable identity it asks for nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheCurrentRequirementIsTheCurrentIdentitys(): void
    {
        config()->set('mfa.applications.' . self::APPLICATION, ['requirement' => 'always']);

        self::assertTrue($this->service()->requirement()->isEmpty());

        $this->actingAs(new PlainUser);

        self::assertTrue($this->service()->requirement()->isEmpty());

        $this->actingAs(TestUser::query()->create(['email' => 'current@example.test', 'mfa_enabled' => false]));

        self::assertSame(['additional_verification' => ['max_age' => null]], $this->service()->requirement()->toArray());
    }

    /**
     * Every application mode, and an application nobody configured.
     *
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
     * An identity whose key is neither a non-empty string nor an integer cannot
     * have its obligation read, so its requirement is refused rather than
     * answered as empty, under every mode, `never` included; the current
     * identity's is refused alike.
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

        $this->service()->requirement();
    }

    /**
     * The gate is asked with this package's setting for the operation as the
     * caller's requirement, made stricter by the one given; an operation the
     * package does not name passes only the one given, or none.
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

        self::assertTrue($this->service()->isFresh('mfa.remove_factor'));
        self::assertTrue($this->service()->isFresh('mfa.remove_factor', $extra));
        self::assertTrue($this->service()->isFresh('billing.change_plan', $extra));
        self::assertTrue($this->service()->isFresh('billing.change_plan', Requirement::none()));
        self::assertTrue($this->service()->isFresh('billing.change_plan'));

        self::assertSame([
            ['mfa.remove_factor', ['additional_verification' => ['max_age' => 300]]],
            ['mfa.remove_factor', ['additional_verification' => ['max_age' => 300], 'minimum_level' => ['level' => 'aal2', 'max_age' => 60]]],
            ['billing.change_plan', ['additional_verification' => ['max_age' => 600], 'minimum_level' => ['level' => 'aal2', 'max_age' => 60]]],
            ['billing.change_plan', null],
            ['billing.change_plan', null],
        ], $asked);
    }

    /**
     * A name that is not an operation's is never fresh, whatever the gate would
     * answer and whatever the caller asks, so it never throws; the gate is not
     * asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testANameThatIsNotAnOperationsIsNeverFresh(): void
    {
        $asked = [];

        $this->container()->instance(FreshnessGate::class, self::gateRecording($asked, true));

        self::assertFalse($this->service()->isFresh('Mfa.Add_Factor', Requirement::none()->withAdditionalVerification(60)));
        self::assertFalse($this->service()->isFresh("mfa.add_factor\n"));
        self::assertFalse($this->service()->isFresh('Not An Operation', Requirement::none()->withMultifactor()));
        self::assertSame([], $asked);
    }

    /**
     * A caller's requirement with a part that carries no maximum age, or one
     * longer than a day, is refused before the gate is asked.
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
            $this->service()->isFresh('mfa.add_factor', Requirement::none()->withAdditionalVerification());
            self::fail('Expected the caller\'s requirement to be refused.');
        } catch (\InvalidArgumentException $exception) {
            $expected = 'A caller\'s requirement must give every part a max_age from 1 to 86400 seconds, which its [additional_verification] part does not.';

            self::assertSame($expected, $exception->getMessage());
        }

        self::assertSame([], $asked);
    }

    /**
     * The requirement an identity requires of its own in the table.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
     */
    private static function identityRequirement(): Requirement
    {
        return Requirement::none()->withAdditionalVerification(600)->withMultifactor(600);
    }

    /**
     * Every setting of the three other sources: whether the identity requires
     * something of its own, whether it is obliged to enrol again, and whether a
     * tenant is active.
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
     * The name of a row of the table: the application's mode, then each other
     * source's setting.
     *
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
     * The serialised requirement a row of the table composes to.
     *
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
     * Every order of the given parts.
     *
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
     * Set the re-enrolment obligation of the identity of the given type and
     * key.
     *
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
            'reenrollment_required' => $required,
            'created_at'            => $now,
            'updated_at'            => $now,
        ]);
    }

    /**
     * A tenant requirement that answers the given requirement for any tenant.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @return \SineMacula\Laravel\Mfa\Contracts\TenantRequirement
     */
    private static function tenantRequiring(Requirement $requirement): TenantRequirement
    {
        return new readonly class ($requirement) implements TenantRequirement {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
             */
            public function __construct(

                /** The requirement every tenant has. */
                private Requirement $requirement,
            ) {}

            /**
             * The tenant's requirement.
             *
             * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
             * @param  string  $application
             * @param  string  $tenant
             * @return \SineMacula\Laravel\Mfa\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(MultiFactorAuthenticatable $identity, string $application, string $tenant): Requirement
            {
                return $this->requirement;
            }
        };
    }

    /**
     * A freshness gate that records each operation and caller's requirement it
     * is asked with, serialised, and answers as given.
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
             * Constructor.
             *
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
             * Record the question and answer it.
             *
             * @param  string  $operation
             * @param  ?\SineMacula\Laravel\Mfa\Requirements\Requirement  $callerRequirement
             * @return bool
             */
            #[\Override]
            public function isFresh(string $operation, ?Requirement $callerRequirement = null): bool
            {
                ($this->record)($operation, $callerRequirement);

                return $this->answer;
            }
        };
    }

    /**
     * Resolve the service under test.
     *
     * @return \SineMacula\Laravel\Mfa\Requirements\RequirementService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): RequirementService
    {
        return $this->container()->make(RequirementService::class);
    }
}
