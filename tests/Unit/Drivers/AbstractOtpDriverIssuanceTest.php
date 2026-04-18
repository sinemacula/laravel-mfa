<?php

declare(strict_types = 1);

namespace Tests\Unit\Drivers;

use SineMacula\Laravel\Mfa\Exceptions\UnsupportedFactorException;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithAbstractOtpDriver;

/**
 * Issuance-side unit tests for `AbstractOtpDriver`.
 *
 * Split from `AbstractOtpDriverTest` so the verify-path, issuance-path, and
 * configuration-path subjects each stay under the project's
 * max-methods-per-class threshold. Shared scaffolding lives on
 * `InteractsWithAbstractOtpDriver` so each file in the family stays focused on
 * its subject without duplicating stub builders.
 *
 * Covers `issueChallenge()` dispatch / persistence ordering, the
 * UnsupportedFactor guard, and the runtime shape of codes minted through the
 * generator (observed via the dispatched payload).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class AbstractOtpDriverIssuanceTest extends TestCase
{
    use InteractsWithAbstractOtpDriver;

    /**
     * `issueChallenge()` must reject any factor that does not implement
     * `EloquentFactor` since OTP drivers persist state between dispatch and
     * verify.
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
     * Test issueChallenge dispatches exactly once to the factor.
     *
     * @return void
     */
    public function testIssueChallengeDispatchesExactlyOnceToFactor(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        self::assertCount(1, $driver->dispatched);
        self::assertSame($factor, $driver->dispatched[0]['factor']);
    }

    /**
     * Test issueChallenge dispatches a well-formed numeric code.
     *
     * @return void
     */
    public function testIssueChallengeDispatchesWellFormedCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        self::assertIsString($code);
        self::assertMatchesRegularExpression('/^\d{6}$/', $code);
    }

    /**
     * Test issueChallenge dispatches before persisting to the factor.
     *
     * @return void
     */
    public function testIssueChallengeDispatchesBeforePersistingToFactor(): void
    {
        $order  = [];
        $driver = $this->makeDriver(orderTracker: $order);
        $factor = $this->createTrackingFactor($order);

        $driver->issueChallenge($factor);

        // Dispatch must have happened before the persist-bearing issueCode()
        // call, and both sides must be observed.
        self::assertSame(['dispatch', 'issueCode', 'persist'], $order);
    }

    /**
     * Test issueChallenge persists the dispatched code onto the factor.
     *
     * @return void
     */
    public function testIssueChallengePersistsDispatchedCodeOntoFactor(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $code = $driver->dispatched[0]['code'];

        $factor->refresh();

        self::assertSame($code, $factor->getCode());
    }

    /**
     * Test issueChallenge persists an expiry alongside the code.
     *
     * @return void
     */
    public function testIssueChallengePersistsExpiryAlongsideCode(): void
    {
        $driver = $this->makeDriver();
        $factor = $this->createEloquentFactor();

        $driver->issueChallenge($factor);

        $factor->refresh();

        self::assertNotNull($factor->getExpiresAt());
    }

    /**
     * If the dispatch step throws the issued code must NOT have been persisted
     * on the factor — issuance is all-or-nothing.
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

        // Nothing was persisted — the model was never saved after the throwing
        // dispatch.
        self::assertNull($factor->getCode());
        self::assertNull($factor->getExpiresAt());
    }

    /**
     * With no alphabet configured the generated code must be zero-padded
     * numeric of the configured length.
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
     * A two-character alphabet must produce codes whose every character is
     * drawn from that alphabet.
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
     * A hex alphabet must produce codes whose every character is a valid hex
     * digit.
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
