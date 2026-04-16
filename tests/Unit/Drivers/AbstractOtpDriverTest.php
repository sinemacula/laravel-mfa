<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use Carbon\Carbon;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithAbstractOtpDriver;

/**
 * Unit tests for `AbstractOtpDriver`.
 *
 * Exercised via a thin anonymous subclass that captures `dispatch()`
 * invocations, allowing the shared issuance / verification logic to be
 * asserted without touching a concrete transport. The driver / factor
 * scaffolding helpers live on the `InteractsWithAbstractOtpDriver`
 * trait so each test file in the family stays focused on its subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class AbstractOtpDriverTest extends TestCase
{
    use InteractsWithAbstractOtpDriver;

    /** @var string Stored-code fixture used as the "expected" side of the verify-mismatch tests. */
    private const string STORED_CODE = '123456';

    /** @var string Distinct second-form code so verify-match tests are not satisfied by accidental collision. */
    private const string MATCHING_CODE = '654321';

    /**
     * `issueChallenge()` must reject any factor that does not
     * implement `EloquentFactor` since OTP drivers persist state
     * between dispatch and verify.
     *
     * @return void
     */
    public function testIssueChallengeThrowsWhenFactorIsNotEloquent(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeNonEloquentFactor();

        $this->expectException(UnsupportedFactorException::class);
        $this->expectExceptionMessage('OTP drivers require a persistable EloquentFactor');

        $driver->issueChallenge($factor);
    }

    /**
     * Issuance must dispatch the code to the transport before
     * persisting it on the factor — observed via a shared call-order
     * tracker.
     *
     * @return void
     */
    public function testIssueChallengeDispatchesThenPersistsInOrder(): void
    {
        $order  = [];
        $driver = $this->makeDriver(orderTracker: $order);
        $factor = $this->createTrackingFactor($order);

        $driver->issueChallenge($factor);

        self::assertCount(1, $driver->dispatched);
        self::assertSame($factor, $driver->dispatched[0]['factor']);

        $code = $driver->dispatched[0]['code'];
        self::assertIsString($code);
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);

        // Dispatch must have happened before the persist-bearing issueCode()
        // call, and both sides must be observed.
        self::assertSame(['dispatch', 'issueCode', 'persist'], $order);

        $factor->refresh();

        self::assertSame($code, $factor->getCode());
        self::assertNotNull($factor->getExpiresAt());
    }

    /**
     * If the dispatch step throws the issued code must NOT have been
     * persisted on the factor — issuance is all-or-nothing.
     *
     * @return void
     */
    public function testIssueChallengeDoesNotPersistWhenDispatchThrows(): void
    {
        $driver = $this->makeDriver(throwOnDispatch: true);
        $factor = $this->createEloquentFactor();

        try {
            $driver->issueChallenge($factor);
            self::fail('Expected dispatch to throw.');
        } catch (\RuntimeException $e) {
            self::assertSame('transport failure', $e->getMessage());
        }

        $factor->refresh();

        // Nothing was persisted — the model was never saved after the
        // throwing dispatch.
        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    /**
     * `verify()` must report false when the factor has no stored
     * code regardless of submitted input.
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
     * `verify()` must report false when the factor has a stored code
     * but no expiry timestamp.
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
            code: self::STORED_CODE,
            expires: Carbon::now()->subMinute(),
        );

        self::assertFalse($driver->verify($factor, self::STORED_CODE));
    }

    /**
     * A submitted code matching the stored code with a future expiry
     * must verify successfully.
     *
     * @return void
     */
    public function testVerifyReturnsTrueForMatchingCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->makeStubFactor(
            code: self::MATCHING_CODE,
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
            code: self::MATCHING_CODE,
            expires: Carbon::now()->addMinutes(5),
        );

        self::assertFalse($driver->verify($factor, '000000'));
    }

    /**
     * OTP drivers do not use a persistent secret — `generateSecret()`
     * must return null.
     *
     * @return void
     */
    public function testGenerateSecretReturnsNull(): void
    {
        $driver = $this->makeDriver();

        self::assertNull($driver->generateSecret());
    }

    /**
     * The driver getters must return the values supplied to the
     * constructor verbatim.
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
     * With no alphabet configured the generated code must be
     * zero-padded numeric of the configured length.
     *
     * @return void
     */
    public function testGeneratedCodeIsZeroPaddedNumericOfConfiguredLength(): void
    {
        $driver = $this->makeDriver(codeLength: 8);
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertSame(8, strlen($code));
        self::assertMatchesRegularExpression('/^\d{8}$/', $code);
    }

    /**
     * The constructor must reject an empty alphabet with a clear
     * `InvalidArgumentException` carrying the distinguishing
     * "received an empty string." suffix.
     *
     * @return void
     */
    public function testConstructorRejectsEmptyAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // Asserting the distinguishing suffix (not just the shared
        // prefix) so a future refactor that swaps the two branch
        // strings cannot silently flip the diagnostic.
        $this->expectExceptionMessage('received an empty string.');

        $this->makeDriver(alphabet: '');
    }

    /**
     * The constructor must reject a single-character alphabet with a
     * clear `InvalidArgumentException` carrying the distinguishing
     * "received a single character." suffix.
     *
     * @return void
     */
    public function testConstructorRejectsSingleCharacterAlphabet(): void
    {
        $this->expectException(\InvalidArgumentException::class);
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
     * A two-character alphabet must produce codes whose every
     * character is drawn from that alphabet.
     *
     * @return void
     */
    public function testGeneratedCodeDrawsFromTwoCharacterAlphabet(): void
    {
        $driver = $this->makeDriver(codeLength: 20, alphabet: 'AB');
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertSame(20, strlen($code));
        self::assertMatchesRegularExpression('/^[AB]{20}$/', $code);
    }

    /**
     * A hex alphabet must produce codes whose every character is a
     * valid hex digit.
     *
     * @return void
     */
    public function testGeneratedCodeDrawsFromHexAlphabet(): void
    {
        $driver = $this->makeDriver(codeLength: 10, alphabet: '0123456789ABCDEF');
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertMatchesRegularExpression('/^[0-9A-F]{10}$/', $code);
    }
}
