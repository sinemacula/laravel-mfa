<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
 * Unit tests for `MfaManager` lookup-style state queries.
 *
 * Covers `getDefaultDriver()`, `requirement()`, `factors()` and `factor()`. The
 * lifecycle-mutation surface lives in a dedicated sibling file
 * (`MfaManagerLifecycleTest`) so each subject stays under the project's
 * max-methods-per-class threshold without losing its cohesive grouping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerStateTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerState;

    /**
     * The shipped default driver should be `'totp'`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testGetDefaultDriverReturnsTotp(): void
    {
        $manager = $this->manager();

        self::assertSame('totp', $manager->getDefaultDriver());
    }

    /**
     * Without an identity in the guard, the sign-in requirement asks for
     * nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementIsEmptyWhenNoIdentityResolved(): void
    {
        self::assertTrue($this->manager()->requirement()->isEmpty());
    }

    /**
     * An identity that does not implement `MultiFactorAuthenticatable` is
     * required to prove nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementIsEmptyWhenIdentityIsNotMfaAuthenticatable(): void
    {
        $plain = new PlainUser;

        $this->actingAs($plain);

        self::assertTrue($this->manager()->requirement()->isEmpty());
    }

    /**
     * An identity that requires an additional factor of its own sign-ins is
     * required one, whatever the application's setting.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementAsksForAnAdditionalVerificationTheIdentityRequires(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'a@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $this->manager()->requirement()->parts());
    }

    /**
     * When the identity requires nothing of its own but its application always
     * requires an additional factor, the requirement still asks for one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementAsksForAnAdditionalVerificationTheApplicationRequires(): void
    {
        config()->set('mfa.applications.web', [
            'requirement'  => 'always',
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);

        $user = TestUser::query()->create([
            'email'       => 'b@example.com',
            'mfa_enabled' => false,
        ]);

        $this->actingAs($user);

        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $this->manager()->requirement()->parts());
    }

    /**
     * When neither the identity nor the application requires anything, the
     * requirement is empty.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementIsEmptyWhenNeitherIdentityNorApplicationRequire(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'c@example.com',
            'mfa_enabled' => false,
        ]);

        $this->actingAs($user);

        self::assertTrue($this->manager()->requirement()->isEmpty());
    }

    /**
     * The requirement of an identity whose auth identifier is non-scalar is
     * refused rather than answered as empty, so the `mfa` middleware fails
     * closed for it, even on an application that never requires a factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementIsRefusedForNonScalarAuthIdentifier(): void
    {
        config()->set('mfa.applications.web', [
            'requirement'  => 'never',
            'first_factor' => ['method' => 'password', 'channel' => 'password'],
        ]);

        $this->actingAs(new NonScalarIdentifierUser);

        $this->expectException(UnsupportedIdentifierException::class);

        $this->manager()->requirement();
    }

    /**
     * Without an identity nothing is listed and nothing is found, rather than
     * throwing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testListsNothingWhenNoIdentity(): void
    {
        self::assertSame([], $this->manager()->factors());
        self::assertNull($this->manager()->factor('anything'));
    }

    /**
     * An identity with no factor rows lists none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testListsNothingWhenIdentityHasNoFactors(): void
    {
        $user = TestUser::query()->create([
            'email'       => 'd@example.com',
            'mfa_enabled' => true,
        ]);

        $this->actingAs($user);

        self::assertSame([], $this->manager()->factors());
    }

    /**
     * The factors are read on every call, so a factor removed since the last
     * call is gone at once and nothing is kept from one request to the next.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReadsTheFactorsOnEveryCall(): void
    {
        $user = $this->makeUserWithFactor();

        $this->actingAs($user);

        $manager = $this->manager();
        $factors = $manager->factors();

        self::assertCount(1, $factors);
        self::assertSame($factors[0]->id, $manager->factor($factors[0]->id)?->id);

        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        self::assertSame([], $manager->factors());
        self::assertNull($manager->factor($factors[0]->id));
    }

    /**
     * An identity whose auth identifier is neither a string nor an integer
     * holds no factor, and listing them does not throw.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testListsNothingForANonScalarAuthIdentifier(): void
    {
        $identity = new NonScalarIdentifierUser;

        Auth::shouldReceive('user')->andReturn($identity);

        self::assertSame([], $this->manager()->factors());
    }
}
