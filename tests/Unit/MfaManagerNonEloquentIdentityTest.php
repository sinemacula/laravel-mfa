<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * Coverage for the FQCN-fallback paths behind the manager.
 *
 * `Support\CurrentIdentity::typeOf()`, which the proof store and recovery code
 * generation all use, branches on whether the identity is a `Model` — Eloquent
 * identities use `getMorphClass()`, non-Eloquent identities fall back to a
 * strict FQCN comparison. The shipped test identities (`TestUser`,
 * `SecondaryUser`, `NonScalarIdentifierUser`) are all Eloquent, so a dedicated
 * non-Eloquent fixture is needed to drive the FQCN branches and keep coverage
 * at 100%.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerNonEloquentIdentityTest extends MfaManagerTestCase
{
    /**
     * Tear down Mockery expectations between test cases.
     *
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
     * Listing factors must complete without throwing for a non-Eloquent
     * identity, and finds only what is stored under its class name and key.
     *
     * @return void
     */
    public function testListingFactorsCompletesForNonEloquentIdentity(): void
    {
        $identity = new NonEloquentIdentity('plain-1', mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);

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

        self::assertSame([$factor->id], array_map(static fn (FactorSummary $summary): string => $summary->id, $this->manager()->factors()));
    }

    /**
     * An identity whose key cannot name a record is refused rather than
     * collapsing distinct identities onto one record, before any driver runs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNonScalarIdentifierIsRefused(): void
    {
        $identity = new NonEloquentIdentity(['nested' => 'array'], mfaEnabled: false);

        Auth::shouldReceive('user')->andReturn($identity);
        Auth::shouldReceive('getDefaultDriver')->andReturn('web');

        $this->expectException(UnsupportedIdentifierException::class);

        $this->manager()->verify(Submission::factor('any', '000000'));
    }

    /**
     * `generateRecoveryCodes()` must accept a non-Eloquent identity and store
     * the new set with the identity's FQCN as the owner type, exercising the
     * FQCN fallback inside the replacement.
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

        self::assertCount(2, $this->container()->make(RecoveryCodeService::class)->generate($identity));

        // Stored rows must carry the identity's FQCN as the owner type, proving
        // the `: $identity::class` fallback fired.
        self::assertSame(
            2,
            RecoveryCode::query()
                ->where('authenticatable_type', NonEloquentIdentity::class)
                ->where('authenticatable_id', 'plain-issue')
                ->count(),
        );
    }

    /**
     * Resolve the package's MFA manager from the container.
     *
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
