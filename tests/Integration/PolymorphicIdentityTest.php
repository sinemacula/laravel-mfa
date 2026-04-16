<?php

declare(strict_types = 1);

namespace Tests\Integration;

use Illuminate\Foundation\Testing\RefreshDatabase;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\SecondaryUser;
use Tests\Fixtures\TestUser;
use Tests\TestCase;

/**
 * Polymorphic-identity integration test.
 *
 * Verifies that the package's polymorphic Factor relation enforces
 * MFA correctly against more than one Eloquent identity class within
 * the same application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class PolymorphicIdentityTest extends TestCase
{
    use RefreshDatabase;

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
            'authenticatable_id'   => (string) $primary->getKey(),
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        Factor::create([
            'authenticatable_type' => $secondary::class,
            'authenticatable_id'   => (string) $secondary->getKey(),
            'driver'               => 'email',
            'recipient'            => $secondary->email,
        ]);

        $this->actingAs($primary);
        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());
        self::assertCount(1, Mfa::getFactors() ?? collect());
        self::assertSame('totp', (Mfa::getFactors()?->first())->getDriver());

        Mfa::clearCache();

        $this->actingAs($secondary);
        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());
        self::assertCount(1, Mfa::getFactors() ?? collect());
        self::assertSame('email', (Mfa::getFactors()?->first())->getDriver());
    }

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
        self::assertFalse(Mfa::shouldUse());

        Mfa::clearCache();

        $this->actingAs($secondary);
        self::assertFalse(Mfa::shouldUse());
    }
}
