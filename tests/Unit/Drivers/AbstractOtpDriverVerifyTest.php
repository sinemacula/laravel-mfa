<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\Carbon;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithAbstractOtpDriver;

/**
 * Verification-side unit tests for `AbstractOtpDriver`.
 *
 * Split from `AbstractOtpDriverTest` so the verify-path, issuance-path, and
 * configuration-path subjects each stay under the project's
 * max-methods-per-class threshold. Covers the constant-time comparison, the
 * stored-code / expiry guards, and the happy-path match — exercised via
 * lightweight stub factors so no persistence is touched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class AbstractOtpDriverVerifyTest extends TestCase
{
    use InteractsWithAbstractOtpDriver;

    /** @var string Stored-code fixture used as the "expected" side of the verify-mismatch tests. */
    private const string STORED_CODE = '123456';

    /** @var string Distinct second-form code so verify-match tests are not satisfied by accidental collision. */
    private const string MATCHING_CODE = '654321';

    /**
     * `verify()` must report false when the factor has no stored code
     * regardless of submitted input.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenStoredCodeIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(code: null, expires: Carbon::now()->addMinute());

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * `verify()` must report false when the factor has a stored code but no
     * expiry timestamp.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenExpiresAtIsNull(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(code: self::STORED_CODE, expires: null);

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * An expired stored code must always fail verification.
     *
     * @return void
     */
    public function testVerifyReturnsFalseWhenCodeHasExpired(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code   : self::STORED_CODE,
            expires: Carbon::now()->subMinute(),
        );

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * A submitted code matching the stored code with a future expiry must
     * verify successfully.
     *
     * @return void
     */
    public function testVerifyReturnsTrueForMatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code   : self::MATCHING_CODE,
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertTrue($driver->verify($factor, self::MATCHING_CODE));
    }

    /**
     * A submitted code that does not match the stored code must fail
     * verification.
     *
     * @return void
     */
    public function testVerifyReturnsFalseForMismatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code   : self::MATCHING_CODE,
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertFalse($driver->verify($factor, '000000'));
    }
}
