<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Identities\UlidIdentity;
use Tests\Fixtures\Identities\UuidIdentity;
use Tests\Fixtures\Lifecycle\Concerns\HoldsIdentityRecords;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class PolymorphicIdentityTest extends TestCase
{
    use ArrangesEnrollment, HoldsIdentityRecords, RefreshDatabase;

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
    #[\Override]
    protected function tearDown(): void
    {
        Relation::requireMorphMap(false);
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * @return void
     */
    public function testFactorsAreScopedToTheirOwningIdentityType(): void
    {
        $primary = TestUser::create([
            'email'       => 'primary@example.test',
            'mfa_enabled' => true,
        ]);

        $secondary = SecondaryUser::create([
            'email'       => 'secondary@example.test',
            'mfa_enabled' => true,
        ]);

        Factor::create([
            'authenticatable_type' => $primary::class,
            'authenticatable_id'   => (string) $primary->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        Factor::create([
            'authenticatable_type' => $secondary::class,
            'authenticatable_id'   => (string) $secondary->id,
            'type'                 => 'email',
            'destination'          => $secondary->email,
        ]);

        // Factors are read per call, scoped by morph class and identifier.
        $this->actingAs($primary);
        self::assertFalse(Mfa::requirement(Callers::current())->isEmpty());

        $primaryFactors = Mfa::factors(Callers::current());
        self::assertCount(1, $primaryFactors);
        self::assertSame('totp', $primaryFactors[0]->type);

        $this->actingAs($secondary);
        self::assertFalse(Mfa::requirement(Callers::current())->isEmpty());

        $secondaryFactors = Mfa::factors(Callers::current());
        self::assertCount(1, $secondaryFactors);
        self::assertSame('email', $secondaryFactors[0]->type);
    }

    /**
     * @return void
     */
    public function testFactorReadsScopeByIdentityClassEvenWhenIdentifiersCollide(): void
    {
        $primary = TestUser::create([
            'email'       => 'shared@example.test',
            'mfa_enabled' => true,
        ]);

        // Share the primary key so only the morph class tells them apart.
        $secondary = SecondaryUser::create([
            'email'       => 'shared-secondary@example.test',
            'mfa_enabled' => true,
        ]);
        $secondary->forceFill(['id' => $primary->getKey()])->saveQuietly();
        $secondary->refresh();

        Factor::create([
            'authenticatable_type' => $primary::class,
            'authenticatable_id'   => (string) $primary->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $this->actingAs($primary);
        self::assertCount(1, Mfa::factors(Callers::current()));

        $this->actingAs($secondary);
        self::assertSame([], Mfa::factors(Callers::current()));
    }

    /**
     * @return void
     */
    public function testEnforcementWorksAcrossBothIdentityClasses(): void
    {
        $primary = TestUser::create([
            'email'       => 'enf-primary@example.test',
            'mfa_enabled' => false,
        ]);

        $secondary = SecondaryUser::create([
            'email'       => 'enf-secondary@example.test',
            'mfa_enabled' => false,
        ]);

        $this->actingAs($primary);
        self::assertTrue(Mfa::requirement(Callers::current())->isEmpty());

        $this->actingAs($secondary);
        self::assertTrue(Mfa::requirement(Callers::current())->isEmpty());
    }

    /**
     * The owner type each is stored under, and how to make one.
     *
     * @return iterable<string, array{string, \Closure(): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable)}>
     */
    public static function identityShapes(): iterable
    {
        yield 'an alias under an enforced morph map' => ['person', static function (): FactorHolder {
            Relation::enforceMorphMap(['person' => FactorHolder::class]);

            return FactorHolder::query()->create(['email' => self::ACCOUNT]);
        }];

        yield 'a UUID key' => [UuidIdentity::class, static fn (): UuidIdentity => UuidIdentity::query()->create(['email' => self::ACCOUNT])];
        yield 'a ULID key' => [UlidIdentity::class, static fn (): UlidIdentity => UlidIdentity::query()->create(['email' => self::ACCOUNT])];
    }

    /**
     * @param  string  $type
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable)  $make
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('identityShapes')]
    public function testAnIdentityEnrollsVerifiesAndIsForgottenUnderItsOwnerTypeAndKey(string $type, \Closure $make): void
    {
        $identity = $make();

        $this->reauthenticated($identity);

        $start        = $this->startedTotp();
        $confirmation = $this->mfa()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start));
        $factor       = $this->pendingFactorOf($start);

        $key = $identity->getKey();

        self::assertTrue($confirmation->isConfirmed());
        self::assertTrue(is_int($key) || is_string($key));
        self::assertSame([$type, (string) $key], [$factor->authenticatable_type, $factor->authenticatable_id]);
        self::assertSame([$factor->id], $identity->authFactors()->pluck('id')->all());
        self::assertTrue($identity->isMfaEnabled());
        self::assertSame([$factor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, Mfa::factors(Callers::current())));
        self::assertSame($factor->id, (new Factor)->resolveRouteBinding($factor->id)?->getKey());
        self::assertSame(10, Mfa::recoveryCodeStatus(Callers::current())?->remaining);

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $this->appCode($start)))->isVerified());

        $this->giveRecords($identity);

        $identity->delete();

        self::assertSame($this->eachTableHolding(0), $this->recordCounts($identity));
    }
}
