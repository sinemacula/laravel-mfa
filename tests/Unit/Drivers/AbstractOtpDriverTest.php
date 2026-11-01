<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Testing\FakeSmsGateway;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithAbstractOtpDriver;

/**
 * Configuration-side unit tests for `AbstractOtpDriver`.
 *
 * Covers the getter accessors, the `startEnrollment()` no-op and confirmation.
 * Issuance- and verification-path coverage lives in the sibling
 * `AbstractOtpDriverIssuanceTest` and `AbstractOtpDriverVerifyTest` so each
 * file in the family stays under the project's max-methods-per-class threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractOtpDriver::class)]
final class AbstractOtpDriverTest extends TestCase
{
    use InteractsWithAbstractOtpDriver;

    /**
     * OTP drivers do not use a persistent secret — `startEnrollment()` must
     * return null.
     *
     * @return void
     */
    public function testStartEnrollmentReturnsNoSecret(): void
    {
        $driver = $this->makeDriver();

        self::assertNull($driver->startEnrollment(new InMemoryFactor));
    }

    /**
     * A delivered code is a one-time password: `otp`.
     *
     * @return void
     */
    public function testTheAmrOfADeliveredCodeIsOtp(): void
    {
        self::assertSame(['otp'], $this->makeDriver()->amr());
    }

    /**
     * Confirming a pending factor checks its code as verification does.
     *
     * @return void
     */
    public function testConfirmationChecksTheCodeAsVerificationDoes(): void
    {
        $driver = $this->makeDriver();
        $factor = new InMemoryFactor(type: 'email', code: '123456', expiresAt: Carbon::now()->addMinute());

        self::assertTrue($driver->confirm($factor, '123456'));
        self::assertFalse($driver->confirm($factor, '654321'));
    }

    /**
     * The driver getters must return the values supplied to the constructor
     * verbatim.
     *
     * @return void
     */
    public function testGettersReturnConstructorValues(): void
    {
        $driver = $this->makeDriver(codeLength: 8, expiry: 15);

        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(15, $driver->getExpiry());
    }

    /**
     * A code is drawn from every number of the configured length, zero
     * included, through the randomness seam, and zero-padded to that length.
     *
     * @return void
     */
    public function testACodeIsDrawnFromEveryNumberOfItsLength(): void
    {
        $draws   = [];
        $gateway = new FakeSmsGateway;
        $driver  = new SmsDriver(
            gateway   : $gateway,
            codeLength: 7,
            randomInt : static function (int $least, int $most) use (&$draws): int {
                $draws[] = [$least, $most];

                return 42;
            },
        );

        $driver->issueChallenge($this->createEloquentFactor());

        self::assertSame([[0, 9999999]], $draws);
        self::assertSame('Your verification code is: 0000042', $gateway->sentTo(self::OTP_DESTINATION)[0]['message']);
    }
}
