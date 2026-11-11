<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\AttemptService;
use SineMacula\Laravel\Mfa\Attempts\AttemptStore;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\CodeService;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Drivers\EmailDriver;
use SineMacula\Laravel\Mfa\Drivers\PasskeyDriver;
use SineMacula\Laravel\Mfa\Drivers\TotpDriver;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\RecoveryCodes\CountingHasher;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;

/**
 * The first factor is read through the application's declaration; a passkey
 * adapter's own statements are outside every budget.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MfaManager::class)]
#[CoversClass(VerificationService::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(AttemptService::class)]
#[CoversClass(AttemptStore::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(CodeService::class)]
#[CoversClass(DeliveredCodes::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(TotpDriver::class)]
#[CoversClass(EmailDriver::class)]
#[CoversClass(PasskeyDriver::class)]
final class VerificationQueryBudgetTest extends PerformanceContractTestCase
{
    use ArrangesVerification;

    /** @var string Matches none of the set. */
    private const string NO_RECOVERY_CODE = 'ZZZZ-ZZZZ-ZZZZ';

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * @return void
     */
    public function testATotpHitInTheAddressesFirstWindow(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        // Reads: factor 1, admission 5, attempt 2, proof 1, evaluation 4.
        // Writes: slot 2, locks 2, step and last use 2, returned 1.
        $result = $this->assertQueryBudget(13, 7, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * @return void
     */
    public function testATotpHitInALaterWindow(): void
    {
        $user   = $this->signedInPerson();
        $first  = $this->totpFactor($user);
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        self::assertTrue($this->mfa()->verify(Callers::current(), Submission::factor($first->id, AuthenticatorApp::code($first)))->isVerified());

        // As the first window, with the slot taken by the update alone.
        $result = $this->assertQueryBudget(13, 6, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * @return void
     */
    public function testATotpMiss(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor, 5);

        // Reads: factor 1, admission 5, attempt 2, window read back 1.
        // Writes: slot 2, locks 2, window 1, identity and factor runs 2.
        $result = $this->assertQueryBudget(9, 7, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
        self::assertSame(1, $this->factorRun($factor));
    }

    /**
     * @return void
     */
    public function testATotpMissThatLocksTheFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['consecutive_failures' => 4]);
        $code   = AuthenticatorApp::code($factor, 5);

        // As a miss: the deadline goes in the update of the factor's run.
        $result = $this->assertQueryBudget(9, 7, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
        self::assertSame(5, $this->factorRun($factor));
        self::assertNotNull($factor->fresh()?->getLockedUntil());
    }

    /**
     * @return void
     */
    public function testATotpSubmissionAgainstALockedFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['consecutive_failures' => 5, 'locked_until' => now()->addHour()]);
        $code   = AuthenticatorApp::code($factor);

        // Reads: factor 1, admission 5. Writes: slot 2, returned 1, lock 1.
        $result = $this->assertQueryBudget(6, 4, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertSame(FailureReason::LOCKED, $result->reason);
    }

    /**
     * @return void
     */
    public function testADeliveredCodeSend(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        // Reads: factor 1, request 5, gateway 5, send 1, open code and caps 3.
        // Writes: slot 2, returned 1, locks 3, code 1.
        $result = $this->assertQueryBudget(15, 7, fn () => $this->mfa()->sendCode(Callers::current(), $factor->id));

        self::assertTrue($result->wasSent());
    }

    /**
     * @return void
     */
    public function testADeliveredCodeHit(): void
    {
        $user = $this->signedInPerson();

        [$challenge, $code, $factor] = $this->sentTo($user);

        // Reads: factor 1, admissions 10, code 1, report 2, proof 1,
        // evaluation 4.
        // Writes: slot 1, locks 3, code's attempt and use 2, last use 1,
        // returned 1.
        $result = $this->assertQueryBudget(19, 8, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::challenge($factor, $challenge, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * @return void
     */
    public function testADeliveredCodeMiss(): void
    {
        $user = $this->signedInPerson();

        [$challenge, $code, $factor] = $this->sentTo($user);

        $wrong = $code === '000000' ? '111111' : '000000';

        // Reads: as a hit up to the report 14, window read back 1.
        // Writes: slot 1, locks 3, code's attempt 1, window and both runs 3.
        $result = $this->assertQueryBudget(15, 8, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::challenge($factor, $challenge, $wrong)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
    }

    /**
     * How many of the ten codes are used.
     *
     * @return iterable<string, array{int}>
     */
    public static function recoverySets(): iterable
    {
        yield from [
            'a full set'        => [0],
            'a partly used set' => [5],
        ];
    }

    /**
     * Statements stay the same at any set size; only the hashing follows it.
     *
     * @param  int  $used
     * @return void
     */
    #[DataProvider('recoverySets')]
    public function testARecoveryCodeHit(int $used): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $code   = $this->recoveryCode($user);
        $hasher = $this->usingSomeOfTheSet($code, $used);

        // Reads: admission 5, attempt 2, redemption 2, proof 1, evaluation 4.
        // Writes: slot 2, returned 1, locks 2, code's use 1.
        $result = $this->assertQueryBudget(14, 6, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::recoveryCode($code)));

        self::assertTrue($result->isVerified());
        self::assertSame(10 - $used, $hasher->checks());
    }

    /**
     * @param  int  $used
     * @return void
     */
    #[DataProvider('recoverySets')]
    public function testARecoveryCodeMiss(int $used): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $hasher = $this->usingSomeOfTheSet($this->recoveryCode($user), $used);

        // Reads: admission 5, attempt 2, redemption 2, window read back 1.
        // Writes: slot 2, locks 2, window and its run 2; no factor has a run.
        $result = $this->assertQueryBudget(10, 6, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::recoveryCode(self::NO_RECOVERY_CODE)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
        self::assertSame(10 - $used, $hasher->checks());
    }

    /**
     * @return void
     */
    public function testAPasskeyHit(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->passkeyFactor($user);

        // Reads: factor 1, admission 5, attempt 2, association 1, first factor
        // again 3, proof 1, evaluation 4.
        // Writes: slot 2, returned 1, locks 2, last use 1.
        $caller = Callers::current();
        $result = $this->assertQueryBudget(17, 6, fn (): VerificationResult => $this->mfa()->verify($caller, Submission::assertion($factor->id, ['id' => self::CREDENTIAL])));

        self::assertTrue($result->isVerified());
    }

    /**
     * The first factor and proofs come from the pending context, not the store.
     *
     * @return void
     */
    public function testATotpHitOnAPendingSession(): void
    {
        $user = $this->person();

        $this->beginSignIn($user, self::PENDING);
        $this->pendingSession($user);

        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        // Reads: factor 1, admission 3, attempt 2, proof 1.
        // Writes: as on an active session.
        $result = $this->assertQueryBudget(7, 7, fn (): VerificationResult => $this->mfa()->verify(Callers::current(), Submission::factor($factor->id, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return array{string, string, string}
     */
    private function sentTo(TestUser $user): array
    {
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        return [$challenge, $code, $factor->id];
    }

    /**
     * Mark codes other than the given one used, then count the hasher's checks.
     *
     * @param  string  $code
     * @param  int  $used
     * @return \Tests\Fixtures\RecoveryCodes\CountingHasher
     */
    private function usingSomeOfTheSet(#[\SensitiveParameter] string $code, int $used): CountingHasher
    {
        $others = RecoveryCode::query()->get()->reject(static fn (RecoveryCode $row): bool => Hash::check($code, $row->code_hash));

        foreach ($others->take($used) as $row) {
            $row->update(['used_at' => now()]);
        }

        $hasher = new CountingHasher($this->container()->make(Hasher::class));

        $this->container()->instance(Hasher::class, $hasher);

        return $hasher;
    }
}
