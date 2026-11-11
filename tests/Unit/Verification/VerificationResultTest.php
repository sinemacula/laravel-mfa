<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Verification\Dumps;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationResult::class)]
final class VerificationResultTest extends TestCase
{
    use BuildsProofs;

    /**
     * @return void
     */
    public function testAVerifiedResultCarriesTheProofAndItsEvaluation(): void
    {
        $proof      = self::proof();
        $evaluation = new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['otp', 'mfa'], [], []);

        $result = VerificationResult::verified($proof, $evaluation, ['otp'], 'totp');

        self::assertTrue($result->isVerified());
        self::assertFalse($result->isFailed());
        self::assertSame($proof, $result->proof);
        self::assertSame($evaluation, $result->evaluation);
        self::assertSame(['otp'], $result->amr);
        self::assertSame('totp', $result->type);
        self::assertNull($result->completion());
        self::assertNull($result->reason);
        self::assertNull($result->detail);
        self::assertNull($result->lockedUntil);
    }

    /**
     * @return void
     */
    public function testAFailedResultCarriesItsReasonAndDetail(): void
    {
        $result = VerificationResult::failed(FailureReason::NOT_FOUND, 'The factor belongs to another identity.');

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isVerified());
        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame('The factor belongs to another identity.', $result->detail);
        self::assertNull($result->proof);
        self::assertNull($result->evaluation);
        self::assertNull($result->lockedUntil);
    }

    /**
     * @return void
     */
    public function testALockoutCarriesTheTimeItLifts(): void
    {
        $until = CarbonImmutable::parse('2026-11-01T10:15:00+00:00');

        $result = VerificationResult::failed(FailureReason::LOCKED, 'Five consecutive failures.', $until);

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame($until, $result->lockedUntil);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBlankDetails(): iterable
    {
        yield 'empty' => [''];
        yield 'spaces' => ['  '];
    }

    /**
     * A failure always says why, internally.
     *
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('provideBlankDetails')]
    public function testABlankDetailIsRefused(string $detail): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The detail of a failed verification must not be blank.');

        VerificationResult::failed(FailureReason::INVALID_CODE, $detail);
    }

    /**
     * A lockout at the failure ceiling does not lift by itself.
     *
     * @return void
     */
    public function testALockoutMayLackItsTime(): void
    {
        $result = VerificationResult::failed(FailureReason::LOCKED, 'Locked.');

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertNull($result->lockedUntil);
    }

    /**
     * Only a lockout carries a time.
     *
     * @return void
     */
    public function testATimeOnAnotherFailureIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Only a failure of reason [locked] carries the time a lockout lifts, not [expired].');

        VerificationResult::failed(FailureReason::EXPIRED, 'The code expired.', CarbonImmutable::now());
    }

    /**
     * The original keeps none.
     *
     * @return void
     */
    public function testACompletionIsCarriedOnACopy(): void
    {
        $evaluation = new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['otp', 'mfa'], [], []);
        $proof      = self::proof();
        $result     = VerificationResult::verified($proof, $evaluation, ['otp'], 'totp', true);
        $completion = new \stdClass;
        $completed  = $result->withCompletion($completion);

        self::assertNull($result->completion());
        self::assertSame($completion, $completed->completion());
        self::assertSame($proof, $completed->proof);
        self::assertSame($evaluation, $completed->evaluation);
        self::assertSame(['otp'], $completed->amr);
        self::assertSame('totp', $completed->type);
        self::assertTrue($completed->refreshesMultifactor);

        $failed = VerificationResult::failed(FailureReason::LOCKED, 'Locked.', CarbonImmutable::parse('2026-11-01T10:15:00+00:00'))->withCompletion(null);

        self::assertSame(FailureReason::LOCKED, $failed->reason);
        self::assertSame('Locked.', $failed->detail);
        self::assertNotNull($failed->lockedUntil);
        self::assertFalse($failed->refreshesMultifactor);
    }

    /**
     * The failure's detail stays in the debug info.
     *
     * @return void
     */
    public function testADumpLeavesOutTheSecrets(): void
    {
        $result = self::verified()->withCompletion((object) ['token' => 'bearer-token']);

        ob_start();
        var_dump($result); // phpcs:ignore SineMaculaLaravel.Debug.DisallowDebugStatements.Found
        $dumped = (string) ob_get_clean();

        self::assertStringNotContainsString('person@example.test', $dumped);
        self::assertStringNotContainsString('bearer-token', $dumped);
        self::assertStringNotContainsString('person@example.test', print_r($result, true));

        $failed = VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.');
        $debug  = $failed->__debugInfo();

        self::assertSame('The code did not match.', $debug['detail']);
        self::assertSame('invalid_code', $debug['reason']);
    }

    /**
     * Laravel's dump helpers and an array cast included.
     *
     * @return void
     */
    public function testNoDumpShowsTheSecrets(): void
    {
        foreach (Dumps::of(self::verified()->withCompletion((object) ['token' => 'bearer-token'])) as $way => $shown) {
            self::assertStringNotContainsString('person@example.test', $shown, $way);
            self::assertStringNotContainsString('bearer-token', $shown, $way);
        }
    }

    /**
     * @return void
     */
    public function testJsonShowsOnlyWhatACallerMayBeTold(): void
    {
        CarbonImmutable::setTestNow('2026-11-01T10:00:00+00:00');

        $result = self::verified()->withCompletion((object) ['token' => 'bearer-token']);
        $proof  = $result->proof;

        self::assertNotNull($proof);

        CarbonImmutable::setTestNow();

        $encoded = (array) json_decode((string) json_encode($result), true);

        self::assertTrue($encoded['verified']);
        self::assertNull($encoded['reason']);
        self::assertSame('totp', $encoded['type']);
        self::assertSame(['otp'], $encoded['amr']);
        self::assertSame('additional_factor', $encoded['kind']);
        self::assertSame($proof->reference, $encoded['reference']);
        self::assertSame($proof->challengeId, $encoded['challenge_id']);
        self::assertSame($proof->provedAt->toIso8601String(), $encoded['proved_at']);
        self::assertSame($proof->binding->toArray(), $encoded['binding']);
        self::assertSame('aal2', $encoded['evaluation']['level'] ?? null);
        self::assertFalse($encoded['refreshes_multifactor']);
        self::assertArrayNotHasKey('detail', $encoded);
        self::assertArrayNotHasKey('completion', $encoded);
        self::assertStringNotContainsString('person@example.test', (string) json_encode($result));

        $until  = CarbonImmutable::parse('2026-11-01T10:15:00+00:00');
        $locked = (array) json_decode((string) json_encode(VerificationResult::failed(FailureReason::LOCKED, 'Secret detail.', $until)), true);

        self::assertFalse($locked['verified']);
        self::assertSame('locked', $locked['reason']);
        self::assertSame('2026-11-01T10:15:00+00:00', $locked['locked_until']);
        self::assertStringNotContainsString('Secret detail.', (string) json_encode($locked));
    }

    /**
     * @return void
     */
    public function testSerializingIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A verification result may hold secrets, so it is never serialised.');

        serialize(VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.'));
    }

    /**
     * @return void
     */
    public function testUnserializingIsRefused(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A verification result may hold secrets, so it is never serialised.');

        VerificationResult::failed(FailureReason::INVALID_CODE, 'The code did not match.')->__unserialize([]);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    private static function verified(): VerificationResult
    {
        $proof = self::proof(['channel' => new Channel(ChannelKind::EMAIL, 'person@example.test'), 'challengeId' => 'challenge-1']);

        return VerificationResult::verified($proof, new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['otp', 'mfa'], [], []), ['otp'], 'totp');
    }
}
