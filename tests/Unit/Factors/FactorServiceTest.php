<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Factors\CustomFactor;
use Tests\Fixtures\Factors\TotpStubFactor;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `FactorService`: the current identity's setup state and factors,
 * read on every call, and the configured factor model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorService::class)]
final class FactorServiceTest extends TestCase
{
    /**
     * A guest is not set up and has no factors.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestIsNotSetUpAndHasNoFactors(): void
    {
        self::assertFalse($this->service()->isSetup());
        self::assertNull($this->service()->getFactors());
    }

    /**
     * An identity with a factor is set up, and its factors are listed.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIdentityWithAFactorIsSetUp(): void
    {
        $user   = $this->signIn();
        $factor = $this->addFactor($user);

        self::assertTrue($this->service()->isSetup());

        $factors = $this->service()->getFactors();

        self::assertNotNull($factors);
        self::assertCount(1, $factors);
        self::assertTrue($factor->is($factors->first()));
    }

    /**
     * An identity without a factor is not set up and has an empty list.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnIdentityWithoutAFactorIsNotSetUp(): void
    {
        $this->signIn();

        self::assertFalse($this->service()->isSetup());
        self::assertCount(0, $this->service()->getFactors() ?? collect([1]));
    }

    /**
     * The setup state and the factors are read on every call, so nothing is
     * kept from one read, or one request, to the next.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReadsTheFactorsOnEveryCall(): void
    {
        $user = $this->signIn();

        self::assertFalse($this->service()->isSetup());
        self::assertCount(0, $this->service()->getFactors() ?? collect([1]));

        $this->addFactor($user);

        self::assertTrue($this->service()->isSetup());
        self::assertCount(1, $this->service()->getFactors() ?? collect());
    }

    /**
     * The shipped model is the factor model by default, and when the setting is
     * null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheShippedModelIsTheDefault(): void
    {
        self::assertSame(Factor::class, $this->service()->factorModel());

        config()->set('mfa.factor.model', null);

        self::assertSame(Factor::class, $this->service()->factorModel());
    }

    /**
     * A configured model that extends `Model` and implements `EloquentFactor`
     * is the factor model.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAConfiguredModelIsTheFactorModel(): void
    {
        config()->set('mfa.factor.model', CustomFactor::class);

        self::assertSame(CustomFactor::class, $this->service()->factorModel());
    }

    /**
     * Misconfigured factor models and the message each is refused with.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function misconfiguredModels(): iterable
    {
        yield 'empty string' => ['', 'mfa.factor.model must be a class string; got [string].'];
        yield 'not a string' => [42, 'mfa.factor.model must be a class string; got [int].'];
        yield 'missing class' => ['App\Missing', 'mfa.factor.model class [App\Missing] does not exist.'];
        yield 'model without the contract' => [PlainUser::class, 'mfa.factor.model class [' . PlainUser::class . '] must extend'];
        yield 'contract without the model' => [TotpStubFactor::class, 'mfa.factor.model class [' . TotpStubFactor::class . '] must extend'];
    }

    /**
     * A misconfigured model is refused with a message naming the problem.
     *
     * @param  mixed  $configured
     * @param  string  $message
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('misconfiguredModels')]
    public function testAMisconfiguredModelIsRefused(mixed $configured, string $message): void
    {
        config()->set('mfa.factor.model', $configured);

        $this->expectException(InvalidModelException::class);
        $this->expectExceptionMessage($message);

        $this->service()->factorModel();
    }

    /**
     * Resolve the factor service.
     *
     * @return \SineMacula\Laravel\Mfa\Factors\FactorService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): FactorService
    {
        return $this->container()->make(FactorService::class);
    }

    /**
     * Create a test user and authenticate as them.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'factors@example.com']);

        $this->actingAs($user);

        return $user;
    }

    /**
     * Add a TOTP factor for the user.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function addFactor(TestUser $user): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
        ]);
    }
}
