<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Enrollment\Concerns\ArrangesEnrollment;
use Tests\Fixtures\Identities\GenericIdentity;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * Drives the class-name fallback of `IdentityType::of()`, since the shipped
 * test identities are all Eloquent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerNonEloquentIdentityTest extends MfaManagerTestCase
{
    use ArrangesEnrollment;

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
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    /**
     * Finds only what is stored under its class name and key.
     *
     * @return void
     */
    public function testListingFactorsCompletesForNonEloquentIdentity(): void
    {
        $identity = new NonEloquentIdentity('plain-1', mfaEnabled: false);

        $this->actingAs($identity);

        $factor = Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-1',
            'type'                 => 'totp',
        ]);

        Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-2',
            'type'                 => 'totp',
        ]);

        self::assertSame([$factor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, $this->manager()->factors(Callers::current())));
    }

    /**
     * Refused before any driver runs, rather than collapsing distinct
     * identities onto one record.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNonScalarIdentifierIsRefused(): void
    {
        $identity = new NonEloquentIdentity(['nested' => 'array'], mfaEnabled: false);

        $this->actingAs($identity);

        $this->expectException(UnsupportedIdentifierException::class);

        $this->manager()->verify(Callers::current(), Submission::factor('any', '000000'));
    }

    /**
     * The new set is stored under the identity's class name.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testGenerateRecoveryCodesAcceptsNonEloquentIdentity(): void
    {
        $identity = new NonEloquentIdentity('plain-issue', mfaEnabled: true);
        $config   = $this->container()->make(Repository::class);

        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('mfa.recovery_codes.count', 2);
        $config->set('mfa.recovery_codes.low_count', 1);
        $config->set('mfa.applications.web', ['recovery_codes' => ['enabled' => true], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);

        Factor::query()->create([
            'authenticatable_type' => NonEloquentIdentity::class,
            'authenticatable_id'   => 'plain-issue',
            'type'                 => 'totp',
            'status'               => 'confirmed',
        ]);

        $this->actingAs($identity);

        self::assertCount(2, $this->container()->make(RecoveryCodeService::class)->generate($identity, 'web'));

        self::assertSame(
            2,
            RecoveryCode::query()
                ->where('authenticatable_type', NonEloquentIdentity::class)
                ->where('authenticatable_id', 'plain-issue')
                ->count(),
        );
    }

    /**
     * Its `authFactors()` is the guide's, so it must match what enrolment
     * stores and nothing of another identity of its class.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWrittenAsDocumentedIsOfferedOnlyTheFactorItEnrolled(): void
    {
        $identity = new GenericIdentity('person-1');

        Factor::query()->create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => GenericIdentity::class,
            'authenticatable_id'   => 'person-2',
            'status'               => 'confirmed',
            'application'          => self::APPLICATION,
        ]);

        $this->reauthenticated($identity);

        $start = $this->startedTotp();

        self::assertTrue($this->manager()->confirmEnrollment(Callers::current(), $this->grantOf($start), $this->appCode($start))->isConfirmed());

        $factor = $this->pendingFactorOf($start);

        self::assertSame([$factor->id], $identity->authFactors()->pluck('id')->all());
        self::assertTrue($identity->isMfaEnabled());
        self::assertSame([$factor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, $this->manager()->offeredFactors(Callers::current())));

        Carbon::setTestNow(CarbonImmutable::now()->addSeconds(30));

        self::assertTrue($this->manager()->verify(Callers::current(), Submission::factor($factor->id, $this->appCode($start)))->isVerified());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\MfaManager
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function manager(): MfaManager
    {
        $manager = $this->container()->make('mfa');
        Assert::assertInstanceOf(MfaManager::class, $manager);

        return $manager;
    }
}
