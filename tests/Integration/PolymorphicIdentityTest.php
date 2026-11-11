<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\SecondaryUser;
use Tests\Fixtures\Identities\TestUser;
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
    use RefreshDatabase;

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
}
