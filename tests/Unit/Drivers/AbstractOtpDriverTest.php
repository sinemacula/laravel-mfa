<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;
use SineMacula\Laravel\Mfa\Drivers\SmsDriver;
use SineMacula\Laravel\Mfa\Testing\FakeSmsGateway;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithAbstractOtpDriver;

/**
 * Configuration-side unit tests for `AbstractOtpDriver`.
 *
 * Covers the getter accessors and the `generateSecret()` no-op. Issuance- and
 * verification-path coverage lives in the sibling
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
     * OTP drivers do not use a persistent secret — `generateSecret()` must
     * return null.
     *
     * @return void
     */
    public function testGenerateSecretReturnsNull(): void
    {
        $driver = $this->makeDriver();

        self::assertNull($driver->generateSecret());
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
        self::assertSame('Your verification code is: 0000042', $gateway->sentTo(self::OTP_RECIPIENT)[0]['message']);
    }
}
