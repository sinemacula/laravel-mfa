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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorService::class)]
final class FactorServiceTest extends TestCase
{
    /**
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
     * @return \SineMacula\Laravel\Mfa\Factors\FactorService
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function service(): FactorService
    {
        return $this->container()->make(FactorService::class);
    }

    /**
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
