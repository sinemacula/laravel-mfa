<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Concerns\HasFactors;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\CustomFactor;
use Tests\Fixtures\Identities\FactorHolder;
use Tests\TestCase;

/**
 * Unit tests for the `HasFactors` trait: an identity model's factors, whether
 * it has a confirmed one, and the defaults of the questions every operation
 * asks first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(HasFactors::class)]
final class HasFactorsTest extends TestCase
{
    use RefreshDatabase;

    /**
     * By default the identity is a person, active, and requires nothing of its
     * own.
     *
     * @return void
     */
    public function testTheDefaultsAreAnActivePersonRequiringNothing(): void
    {
        $identity = new FactorHolder;

        self::assertTrue($identity->canHoldFactors());
        self::assertTrue($identity->isMfaActive());
        self::assertNull($identity->requiresAdditionalFactor());
    }

    /**
     * The identity's factors are its own, of the shipped model.
     *
     * @return void
     */
    public function testTheFactorsAreTheIdentitysOwn(): void
    {
        $identity = $this->createHolder('one@example.test');
        $other    = $this->createHolder('two@example.test');

        $own = $this->createFactor($identity, 'confirmed');
        $this->createFactor($other, 'confirmed');

        $factors = $identity->authFactors()->get();

        self::assertInstanceOf(Factor::class, $identity->authFactors()->getModel());
        self::assertSame([$own->id], $factors->modelKeys());
    }

    /**
     * The factors are of the configured factor model.
     *
     * @return void
     */
    public function testTheFactorsAreOfTheConfiguredModel(): void
    {
        $this->container()->make(Repository::class)->set('mfa.factor.model', CustomFactor::class);

        self::assertInstanceOf(CustomFactor::class, (new FactorHolder)->authFactors()->getModel());
    }

    /**
     * Only a confirmed factor enables MFA: a pending one does not.
     *
     * @return void
     */
    public function testOnlyAConfirmedFactorEnablesMfa(): void
    {
        $identity = $this->createHolder('one@example.test');

        self::assertFalse($identity->isMfaEnabled());

        $this->createFactor($identity, 'pending');

        self::assertFalse($identity->isMfaEnabled());

        $this->createFactor($identity, 'confirmed');

        self::assertTrue($identity->isMfaEnabled());
    }

    /**
     * Deleting the identity deletes its factors, and only its own.
     *
     * @return void
     */
    public function testDeletingTheIdentityDeletesItsFactors(): void
    {
        $identity = $this->createHolder('one@example.test');
        $other    = $this->createHolder('two@example.test');

        $this->createFactor($identity, 'confirmed');
        $kept = $this->createFactor($other, 'confirmed');

        $identity->delete();

        self::assertSame([$kept->id], Factor::query()->pluck('id')->all());
    }

    /**
     * Create an identity.
     *
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\FactorHolder
     */
    private function createHolder(string $email): FactorHolder
    {
        return FactorHolder::query()->create(['email' => $email]);
    }

    /**
     * Create a factor of the identity with the given status.
     *
     * @param  \Tests\Fixtures\Identities\FactorHolder  $identity
     * @param  string  $status
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function createFactor(FactorHolder $identity, string $status): Factor
    {
        return Factor::query()->create([
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
            'type'                 => 'totp',
            'status'               => $status,
        ]);
    }
}
