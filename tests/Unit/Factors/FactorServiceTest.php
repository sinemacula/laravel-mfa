<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;
use SineMacula\Laravel\Mfa\Exceptions\InvalidModelException;
use SineMacula\Laravel\Mfa\Factors\FactorService;
use SineMacula\Laravel\Mfa\Factors\FactorSummary;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Factors\CustomFactor;
use Tests\Fixtures\Factors\TotpStubFactor;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `FactorService`: the current identity's factors as summaries, read
 * on every call, and the configured factor model.
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
     * A guest has no factors, and finds none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuestHasNoFactors(): void
    {
        self::assertSame([], $this->service()->factors(Callers::current()));
        self::assertNull($this->service()->factor(Callers::current(), 'anything'));
    }

    /**
     * Every factor is listed as a summary with its status: pending ones and
     * those enrolled through another application included, and one disabled at
     * the failure ceiling saying so.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testEveryFactorIsListedWithItsStatus(): void
    {
        $user      = $this->signIn();
        $confirmed = $this->addFactor($user, ['status' => 'confirmed', 'application' => 'web']);
        $pending   = $this->addFactor($user, ['status' => 'pending', 'application' => 'web']);
        $elsewhere = $this->addFactor($user, ['status' => 'confirmed', 'application' => 'another']);
        $disabled  = $this->addFactor($user, ['status' => 'confirmed', 'application' => 'web', 'disabled_at' => CarbonImmutable::now()]);

        $summaries = [];

        foreach ($this->service()->factors(Callers::current()) as $summary) {
            $summaries[$summary->id] = $summary;
        }

        self::assertCount(4, $summaries);
        self::assertSame(FactorStatus::CONFIRMED, $summaries[$confirmed->id]->status);
        self::assertSame(FactorStatus::PENDING, $summaries[$pending->id]->status);
        self::assertArrayHasKey($elsewhere->id, $summaries);
        self::assertFalse($summaries[$confirmed->id]->disabled);
        self::assertTrue($summaries[$disabled->id]->disabled);
        self::assertTrue($summaries[$disabled->id]->jsonSerialize()['disabled']);
    }

    /**
     * The preferred factor comes first, then the others by id.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePreferredFactorComesFirstThenById(): void
    {
        $user = $this->signIn();

        // Full length, as the column is fixed width and PostgreSQL pads it.
        [$a, $b, $c] = array_map(static fn (string $letter): string => str_repeat($letter, 26), ['a', 'b', 'c']);

        foreach ([$c, $a, $b] as $id) {
            $factor = $this->addFactor($user, ['status' => 'confirmed']);

            DB::table('mfa_factors')->where('id', $factor->id)->update(['id' => $id, 'preferred' => $id === $b]);
        }

        self::assertSame([$b, $a, $c], array_map(static fn (FactorSummary $summary): string => $summary->id, $this->service()->factors(Callers::current())));
    }

    /**
     * One factor is found by its id; another person's, an unknown id and an id
     * of any other shape are not, and an integer id finds nothing it does not
     * name exactly.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOneFactorIsFoundOnlyByItsOwnersExactId(): void
    {
        $user    = $this->signIn();
        $factor  = $this->addFactor($user);
        $another = TestUser::query()->create(['email' => 'another@example.test']);
        $theirs  = $this->addFactor($another);

        self::assertSame($factor->id, $this->service()->factor(Callers::current(), $factor->id)?->id);
        self::assertNull($this->service()->factor(Callers::current(), $theirs->id));
        self::assertNull($this->service()->factor(Callers::current(), 'missing'));
        self::assertNull($this->service()->factor(Callers::current(), strtoupper($factor->id)));
        self::assertNull($this->service()->factor(Callers::current(), ['id' => $factor->id]));
    }

    /**
     * The factors are read on every call, so nothing is kept from one read, or
     * one request, to the next.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testReadsTheFactorsOnEveryCall(): void
    {
        $user = $this->signIn();

        self::assertCount(0, $this->service()->factors(Callers::current()));

        $this->addFactor($user);

        self::assertCount(1, $this->service()->factors(Callers::current()));
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
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function addFactor(TestUser $user, array $attributes = []): Factor
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor */
        return Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => 'JBSWY3DPEHPK3PXP',
            ...$attributes,
        ]);
    }
}
