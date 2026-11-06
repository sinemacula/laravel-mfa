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
 * Polymorphic-identity integration test.
 *
 * Verifies that the package's polymorphic Factor relation enforces MFA
 * correctly against more than one Eloquent identity class within the same
 * application.
 *
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
     * Factors persisted against one identity class must not leak into a sibling
     * identity class — the polymorphic relation scopes by
     * `authenticatable_type` correctly.
     *
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

        // Identity switches need nothing in between: the factors are read for
        // the current identity on every call, scoped by morph class as well as
        // identifier.
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
     * Two MFA-capable identity classes that share a primary-key value
     * (`User #1` and `Admin #1`) MUST read their own factors within the same
     * request — without scoping by class the second identity would see the
     * first identity's factor.
     *
     * @return void
     */
    public function testFactorReadsScopeByIdentityClassEvenWhenIdentifiersCollide(): void
    {
        $primary = TestUser::create([
            'email'       => 'shared@example.test',
            'mfa_enabled' => true,
        ]);

        // Force the secondary onto the same primary-key value so the only thing
        // distinguishing the two identities is the morph class.
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
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);

        $this->actingAs($primary);
        self::assertCount(1, Mfa::factors(Callers::current()));

        $this->actingAs($secondary);
        // Without per-class scoping this would erroneously list the primary's
        // factor, as it shares the id.
        self::assertSame([], Mfa::factors(Callers::current()));
    }

    /**
     * The sign-in requirement must be empty for both identity classes alike
     * when neither requires anything of its own.
     *
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
