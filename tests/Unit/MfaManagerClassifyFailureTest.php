<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Events\MfaVerificationFailed;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\TestUser;
use Tests\Unit\Concerns\InteractsWithMfaManagerVerify;

/**
 * Unit tests for `MfaManager::verify()` reason mapping.
 *
 * Split out from `MfaManagerVerifyTest` so each cohesive subject — the verify
 * orchestration pipeline vs. the failure-reason classifier — has a dedicated
 * suite under the project's max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
final class MfaManagerClassifyFailureTest extends MfaManagerTestCase
{
    use InteractsWithMfaManagerVerify;

    /** @var string Sentinel mismatch code used to drive the failure-path assertions. */
    private const string WRONG_CODE = '000000';

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
     * A TOTP-shape factor with no stored secret fails as `not_confirmed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsNotConfirmedForTotpShapedFactorWithoutSecret(): void
    {
        $user = TestUser::query()->create(['email' => 'cf1@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(type: 'totp', authenticatable: $user);

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::NOT_CONFIRMED,
        );
    }

    /**
     * A TOTP factor with a stored secret whose verification still fails fails
     * as `invalid_code`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsInvalidCodeForTotpSecretMismatch(): void
    {
        $user = TestUser::query()->create(['email' => 'cf3@example.com']);

        $this->actingAs($user);

        $factor = new InMemoryFactor(
            type         : 'totp',
            secret         : 'JBSWY3DPEHPK3PXP',
            authenticatable: $user,
        );

        $driver = \Mockery::mock(FactorDriver::class);
        $driver->shouldReceive('verify')->once()->andReturnFalse();

        $this->stubDriver('totp', $driver);

        Event::fake();

        $this->manager()->verify('totp', $factor, self::WRONG_CODE);

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::INVALID_CODE,
        );
    }

    /**
     * Rows of a delivered code's failure: what the test does after the code is
     * sent, the code it then submits, and the reason and detail it fails with.
     *
     * @return iterable<string, array{\Closure(\Tests\Unit\MfaManagerClassifyFailureTest, \SineMacula\Laravel\Mfa\Models\Factor, string): void, ?string, \SineMacula\Laravel\Mfa\Enums\FailureReason, string}>
     */
    public static function deliveredCodeFailures(): iterable
    {
        $nothing = static function (): void {};

        yield 'a wrong code' => [$nothing, self::WRONG_CODE, FailureReason::INVALID_CODE, 'The code did not match.'];
        yield 'an expired code' => [
            static function (self $test): void {
                $test->travel(11)->minutes();
            },
            null,
            FailureReason::EXPIRED,
            'The code has expired.',
        ];
        yield 'a used code' => [
            static function (self $test, Factor $factor, string $code): void {
                $test->manager()->verify('email', $factor, $code);
            },
            null,
            FailureReason::REPLAYED,
            'The code was already used.',
        ];
    }

    /**
     * A delivered code fails with the reason its check found, and its detail.
     *
     * @param  \Closure(\Tests\Unit\MfaManagerClassifyFailureTest, \SineMacula\Laravel\Mfa\Models\Factor, string): void  $after
     * @param  ?string  $submitted
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    #[DataProvider('deliveredCodeFailures')]
    public function testClassifyFailureReportsWhatTheDeliveredCodeCheckFound(\Closure $after, ?string $submitted, FailureReason $reason, string $detail): void
    {
        $factor = $this->emailFactor('cf6@example.com');
        $sender = FakeEmailSender::fake($this->container());

        $this->manager()->challenge('email', $factor);

        $code = $sender->lastCodeTo('cf6@example.com');

        self::assertNotNull($code);

        $after($this, $factor, $code);

        Event::fake([MfaVerificationFailed::class]);

        self::assertFalse($this->manager()->verify('email', $factor, $submitted ?? $code));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === $reason && $event->detail === $detail,
        );
    }

    /**
     * A delivered-code factor with no code sent fails as `expired`: there is no
     * live code to check against.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testClassifyFailureReturnsExpiredWhenNoCodeWasSent(): void
    {
        $factor = $this->emailFactor('cf7@example.com');

        FakeEmailSender::fake($this->container());
        Event::fake([MfaVerificationFailed::class]);

        self::assertFalse($this->manager()->verify('email', $factor, self::WRONG_CODE));

        Event::assertDispatched(
            MfaVerificationFailed::class,
            static fn (MfaVerificationFailed $event): bool => $event->reason === FailureReason::EXPIRED
                && $event->detail                                            === 'No code was sent for this factor, session, application and purpose.',
        );
    }

    /**
     * Sign in as a new user with a stored email factor.
     *
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Models\Factor
     */
    private function emailFactor(string $address): Factor
    {
        $user = TestUser::query()->create(['email' => $address]);

        $this->actingAs($user);

        return Factor::query()->create([
            'authenticatable_type' => $user->getMorphClass(),
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'email',
            'destination'          => $address,
        ]);
    }
}
