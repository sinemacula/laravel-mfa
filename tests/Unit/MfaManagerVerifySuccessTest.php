<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\Factor as FactorContract;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\Events\MfaVerified;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerVerify;

/**
 * Unit tests covering the verify success path on `MfaManager::verify()`: the
 * factor's state and the proof recorded on the identity's sign-in.
 *
 * Split out from `MfaManagerVerifyTest` so the success-scenario and
 * proof-recording assertions stay cohesive and each test class remains under
 * the project's max-methods threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerVerifySuccessTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerVerify;

    /** @var string Canonical right-shape OTP fixture used for the success-path assertions. */
    private const string VALID_CODE = '123456';

    /**
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (class_exists(\Mockery::class)) {
            \Mockery::close();
        }

        parent::tearDown();
    }

    /**
     * Test successful Eloquent verify returns true.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessReturnsTrueForEloquentFactor(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        self::assertTrue($this->manager()->verify('email', $factor, self::VALID_CODE));
    }

    /**
     * Test successful Eloquent verify resets the attempt counter.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessResetsAttemptCounter(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $factor->refresh();

        self::assertSame(0, $factor->getAttempts());
    }

    /**
     * Test successful Eloquent verify stamps the factor's last use.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessStampsLastUseOnFactor(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $factor->refresh();

        self::assertNotNull($factor->getLastUsedAt());
    }

    /**
     * Test successful Eloquent verify clears the pending code.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessClearsPendingCode(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $factor->refresh();

        self::assertNull($factor->getCode());
    }

    /**
     * Test successful Eloquent verify dispatches MfaVerified event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessDispatchesVerifiedEvent(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        Event::fake();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        Event::assertDispatched(MfaVerified::class);
    }

    /**
     * Test successful Eloquent verify does not dispatch a failure event.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessDoesNotDispatchFailureEvent(): void
    {
        [$factor] = $this->seedEloquentVerifySuccessScenario();

        Event::fake();

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        Event::assertNotDispatched(MfaVerificationFailed::class);
    }

    /**
     * Test verify success on a signed-in session records an additional factor
     * proof on the driver's channel, named by the factor's destination.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessRecordsAProofOnTheSignIn(): void
    {
        [$factor, $driver, $user] = $this->seedEloquentVerifySuccessScenario();

        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::EMAIL);

        Auth::login($user);

        $this->manager()->verify('email', $factor, self::VALID_CODE);

        $proofs = $this->manager()->proofs();

        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame('email', $proofs[0]->method);
        self::assertSame($factor->getKey(), $proofs[0]->reference);
        self::assertSame(['kind' => 'email', 'reference' => 'v2@example.com'], $proofs[0]->channel?->toArray());
    }

    /**
     * Test verify success without a sign-in records nothing and never asks the
     * driver for its channel.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessWithoutASignInRecordsNothing(): void
    {
        [$factor, $driver] = $this->seedEloquentVerifySuccessScenario();

        $driver->shouldNotReceive('channelKind');

        self::assertTrue($this->manager()->verify('email', $factor, self::VALID_CODE));
        self::assertSame([], $this->manager()->proofs());
    }

    /**
     * Test verify success through a driver whose channel cannot carry a factor
     * records nothing, even on a signed-in session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testVerifySuccessOnAnUnknownChannelRecordsNothing(): void
    {
        [$factor, $driver, $user] = $this->seedEloquentVerifySuccessScenario();

        $driver->shouldReceive('channelKind')->andReturn(ChannelKind::UNKNOWN);

        Auth::login($user);

        self::assertTrue($this->manager()->verify('email', $factor, self::VALID_CODE));
        self::assertSame([], $this->manager()->proofs());
    }

    /**
     * Stage the Eloquent-factor success scenario, acting as the user without
     * signing them in, and return the persisted factor, the stubbed driver and
     * the user for the assertions to observe.
     *
     * @formatter:off
     *
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor, 1: \Mockery\MockInterface&\SineMacula\Laravel\Mfa\Contracts\FactorDriver, 2: \Tests\Fixtures\Identities\TestUser}
     *
     * @formatter:on
     */
    private function seedEloquentVerifySuccessScenario(): array
    {
        $user = TestUser::query()->create(['email' => 'v2@example.com']);

        $this->actingAs($user);

        $factor = Factor::query()->create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => 'v2@example.com',
            'code'                 => self::VALID_CODE,
            'expires_at'           => Carbon::now()->addMinutes(10),
            'attempts'             => 1,
        ]);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')
            ->with(\Mockery::type(FactorContract::class), self::VALID_CODE)
            ->andReturnTrue();

        $this->stubDriver('email', $driver);

        return [$factor, $driver, $user];
    }
}
