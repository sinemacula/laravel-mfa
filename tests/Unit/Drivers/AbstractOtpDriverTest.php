<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use SineMacula\Laravel\Mfa\Exceptions\InvalidDriverConfigurationException;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithAbstractOtpDriver;

/**
 * Configuration-side unit tests for `AbstractOtpDriver`.
 *
 * Covers constructor-time validation, getter accessors, and the
 * `generateSecret()` no-op. Issuance- and verification-path coverage lives in
 * the sibling `AbstractOtpDriverIssuanceTest` and `AbstractOtpDriverVerifyTest`
 * so each file in the family stays under the project's max-methods-per-class
 * threshold.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
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
        $driver = $this->makeDriver(codeLength: 8, expiry: 15, maxAttempts: 5);

        self::assertSame(8, $driver->getCodeLength());
        self::assertSame(15, $driver->getExpiry());
        self::assertSame(5, $driver->getMaxAttempts());
        self::assertNull($driver->getAlphabet());
    }

    /**
     * The constructor must reject an empty alphabet with a clear
     * `InvalidDriverConfigurationException` carrying the distinguishing
     * "received an empty string." suffix.
     *
     * @return void
     */
    public function testConstructorRejectsEmptyAlphabet(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        // Asserting the distinguishing suffix (not just the shared prefix) so a
        // future refactor that swaps the two branch strings cannot silently
        // flip the diagnostic.
        $this->expectExceptionMessage('received an empty string.');

        $this->makeDriver(alphabet: '');
    }

    /**
     * The constructor must reject a single-character alphabet with a clear
     * `InvalidDriverConfigurationException` carrying the distinguishing
     * "received a single character." suffix.
     *
     * @return void
     */
    public function testConstructorRejectsSingleCharacterAlphabet(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        $this->expectExceptionMessage('received a single character.');

        $this->makeDriver(alphabet: 'A');
    }

    /**
     * `getAlphabet()` must return the configured alphabet verbatim.
     *
     * @return void
     */
    public function testGetAlphabetReturnsConfiguredValue(): void
    {
        $driver = $this->makeDriver(alphabet: 'ABCDEF');

        self::assertSame('ABCDEF', $driver->getAlphabet());
    }

    /**
     * A zero code length is a deployment-time bug — the numeric path would
     * otherwise mint a one-character `"0"` code, and the alphabet path would
     * return an empty string. Reject at construction so the misconfiguration
     * surfaces in the stack trace rather than the user flow.
     *
     * @return void
     */
    public function testConstructorRejectsZeroCodeLength(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        $this->expectExceptionMessage('OTP code length must be at least 1');

        $this->makeDriver(codeLength: 0);
    }

    /**
     * A negative code length is nonsensical — reject at construction for the
     * same reason a zero length is rejected.
     *
     * @return void
     */
    public function testConstructorRejectsNegativeCodeLength(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        $this->expectExceptionMessage('OTP code length must be at least 1');

        $this->makeDriver(codeLength: -1);
    }

    /**
     * A zero expiry would make every issued code expired on arrival — reject at
     * construction so the broken window surfaces at boot rather than on the
     * first verification attempt.
     *
     * @return void
     */
    public function testConstructorRejectsZeroExpiry(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        $this->expectExceptionMessage('OTP expiry must be at least 1 minute');

        $this->makeDriver(expiry: 0);
    }

    /**
     * A negative expiry is nonsensical — reject at construction for the same
     * reason a zero expiry is rejected.
     *
     * @return void
     */
    public function testConstructorRejectsNegativeExpiry(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        $this->expectExceptionMessage('OTP expiry must be at least 1 minute');

        $this->makeDriver(expiry: -5);
    }

    /**
     * A negative `maxAttempts` would never match the `>=` threshold the manager
     * uses to apply a lockout — reject at construction so the misconfiguration
     * cannot silently disable lockouts.
     *
     * @return void
     */
    public function testConstructorRejectsNegativeMaxAttempts(): void
    {
        $this->expectException(InvalidDriverConfigurationException::class);
        $this->expectExceptionMessage('OTP max attempts must be zero or greater');

        $this->makeDriver(maxAttempts: -1);
    }
}
