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
 * Verifies that the package's polymorphic Factor relation enforces MFA
 * correctly against more than one Eloquent identity class within the same
 * application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class PolymorphicIdentityTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Factors persisted against one identity class must not leak into a sibling
     * identity class — the polymorphic relation scopes by
     * `authenticatable_type` correctly.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        Factor::create([
            'authenticatable_type' => $secondary::class,
            'authenticatable_id'   => (string) $secondary->id,
            'driver'               => 'email',
            'recipient'            => $secondary->email,
        ]);

        // No manual `Mfa::clearCache()` between identity switches — the
        // manager's per-identity cache scopes by morph class as well as
        // identifier, so two distinct authenticatable classes sharing a primary
        // key value get distinct cache slots.
        $this->actingAs($primary);
        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());

        $primaryFactors = Mfa::getFactors();
        self::assertNotNull($primaryFactors);
        self::assertCount(1, $primaryFactors);
        $primaryFactor = $primaryFactors->first();
        self::assertNotNull($primaryFactor);
        self::assertSame('totp', $primaryFactor->getDriver());

        $this->actingAs($secondary);
        self::assertTrue(Mfa::shouldUse());
        self::assertTrue(Mfa::isSetup());

        $secondaryFactors = Mfa::getFactors();
        self::assertNotNull($secondaryFactors);
        self::assertCount(1, $secondaryFactors);
        $secondaryFactor = $secondaryFactors->first();
        self::assertNotNull($secondaryFactor);
        self::assertSame('email', $secondaryFactor->getDriver());
    }

    /**
     * Two MFA-capable identity classes that share a primary-key value (`User
     * #1` and `Admin #1`) MUST get distinct cache entries within the same
     * request — without that scoping the second identity inherits the first
     * identity's cached state.
     *
     * @return void
     */
    public function testCacheKeysScopeByIdentityClassEvenWhenIdentifiersCollide(): void
    {
        $primary = TestUser::create([
            'email'       => 'shared@example.test',
            'mfa_enabled' => true,
        ]);

        // Force the secondary onto the same primary-key value so the only thing
        // distinguishing the two identities in the cache is the morph class.
        // Pre-key-collision the cache prefix would produce identical keys and
        // one identity's setup state would win the cache slot.
        $secondary = SecondaryUser::create([
            'email'       => 'shared-secondary@example.test',
            'mfa_enabled' => true,
        ]);
        $secondary->forceFill(['id' => $primary->getKey()])->saveQuietly();
        $secondary->refresh();

        // Only the primary identity owns a factor.
        Factor::create([
            'authenticatable_type' => $primary::class,
            'authenticatable_id'   => (string) $primary->id,
            'driver'               => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $this->actingAs($primary);
        self::assertTrue(Mfa::isSetup());

        $this->actingAs($secondary);
        // Without per-class cache scoping this would erroneously return true
        // because the cached "isSetup" entry for the shared id would still be
        // in memory.
        self::assertFalse(Mfa::isSetup());
    }

    /**
     * The `shouldUse()` enforcement check must respond identically across both
     * identity classes when neither opts in.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
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
        self::assertFalse(Mfa::shouldUse());

        $this->actingAs($secondary);
        self::assertFalse(Mfa::shouldUse());
    }
}
