<?php

declare(strict_types = 1);

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerState;

/**
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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementIsEmptyWhenNoIdentityResolved(): void
    {
        self::assertTrue($this->manager()->requirement(Callers::current())->isEmpty());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRequirementIsEmptyWhenIdentityIsNotMfaAuthenticatable(): void
    {
        $plain = new PlainUser;

        $this->actingAs($plain);

        self::assertTrue($this->manager()->requirement(Callers::current())->isEmpty());
    }

    /**
     * Whatever the application's setting.
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

        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $this->manager()->requirement(Callers::current())->parts());
    }

    /**
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

        self::assertSame([RequirementPart::ADDITIONAL_VERIFICATION], $this->manager()->requirement(Callers::current())->parts());
    }

    /**
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

        self::assertTrue($this->manager()->requirement(Callers::current())->isEmpty());
    }

    /**
     * Refused rather than answered as empty, so the `mfa` middleware fails
     * closed even where no factor is required.
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

        $this->manager()->requirement(Callers::current());
    }

    /**
     * Rather than throwing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testListsNothingWhenNoIdentity(): void
    {
        self::assertSame([], $this->manager()->factors(Callers::current()));
        self::assertNull($this->manager()->factor(Callers::current(), 'anything'));
    }

    /**
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

        self::assertSame([], $this->manager()->factors(Callers::current()));
    }

    /**
     * So a removed factor is gone at once and nothing carries between requests.
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
        $factors = $manager->factors(Callers::current());

        self::assertCount(1, $factors);
        self::assertSame($factors[0]->id, $manager->factor(Callers::current(), $factors[0]->id)?->id);

        Factor::query()->where('authenticatable_id', $user->getKey())->delete();

        self::assertSame([], $manager->factors(Callers::current()));
        self::assertNull($manager->factor(Callers::current(), $factors[0]->id));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testListsNothingForANonScalarAuthIdentifier(): void
    {
        $identity = new NonScalarIdentifierUser;

        $this->actingAs($identity);

        self::assertSame([], $this->manager()->factors(Callers::current()));
    }
}
