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
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\RecoveryCodes\CountingHasher;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;

/**
 * The statements each branch of a verification makes, read and written, with
 * each one named in a ledger beside its budget. The application declares its
 * first factor, so the first factor is read through its declaration.
 *
 * A passkey's statements are this package's own: the adapter behind the gateway
 * makes its own, which are outside the budget, and so are those of a completion
 * an adapter binds for a pending session.
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

    /** @var string A code submitted that matches none of the set. */
    private const string NO_RECOVERY_CODE = 'ZZZZ-ZZZZ-ZZZZ';

    /**
     * Arrange the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->arrangeVerification();
    }

    /**
     * A TOTP code accepted from an address with no window yet.
     *
     * @return void
     */
    public function testATotpHitInTheAddressesFirstWindow(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        // Reads (13): the factor found (1); under the lock, its factors (1);
        // the admission's first factor, whose session proofs, declaration and
        // trust each read the generation (3), and its state (1); under the
        // attempt's lock, its factors and state (2); the proof's generation
        // (1); the evaluation's proofs, declaration and trust (3); and the
        // re-enrolment obligation (1). The factor's lockout is on the row its
        // factors read, so it takes no statement of its own.
        //
        // Writes (7): the address's slot, an update that finds no row and an
        // insert (2); the identity's lock for the verification and for the
        // attempt inside it (2); the step's compare-and-set and the factor's
        // last use (2); and the slot given back (1). The proof goes to the
        // session, not the database.
        $result = $this->assertQueryBudget(13, 7, fn (): VerificationResult => $this->mfa()->verify(Submission::factor($factor->id, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * A TOTP code accepted from an address already in a window: one statement
     * fewer, as the update finds the row.
     *
     * @return void
     */
    public function testATotpHitInALaterWindow(): void
    {
        $user   = $this->signedInPerson();
        $first  = $this->totpFactor($user);
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor);

        self::assertTrue($this->mfa()->verify(Submission::factor($first->id, AuthenticatorApp::code($first)))->isVerified());

        // As the first window, with the address's slot taken by the update
        // alone: reads (13), writes (6).
        $result = $this->assertQueryBudget(13, 6, fn (): VerificationResult => $this->mfa()->verify(Submission::factor($factor->id, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * A wrong TOTP code counts in the identity's window and both runs, and
     * keeps the address's slot.
     *
     * @return void
     */
    public function testATotpMiss(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = AuthenticatorApp::code($factor, 5);

        // Reads (9): the factor found (1); the admission's factors, first
        // factor and state (5); the attempt's factors and state (2); the
        // identity's window read back (1).
        //
        // Writes (7): the address's slot (2); the two locks (2); the identity's
        // window counted in one upsert (1); the identity's and the factor's
        // runs (2). No step, no proof, no slot given back.
        $result = $this->assertQueryBudget(9, 7, fn (): VerificationResult => $this->mfa()->verify(Submission::factor($factor->id, $code)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
        self::assertSame(1, $this->factorRun($factor));
    }

    /**
     * The wrong code that locks the factor costs what any other miss does: its
     * deadline goes in the one update that counts its run.
     *
     * @return void
     */
    public function testATotpMissThatLocksTheFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['consecutive_failures' => 4]);
        $code   = AuthenticatorApp::code($factor, 5);

        // Reads (9) and writes (7): as a miss, with the deadline in the update of
        // the factor's run rather than a statement of its own.
        $result = $this->assertQueryBudget(9, 7, fn (): VerificationResult => $this->mfa()->verify(Submission::factor($factor->id, $code)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
        self::assertSame(5, $this->factorRun($factor));
        self::assertNotNull($factor->fresh()?->getLockedUntil());
    }

    /**
     * A locked factor is refused before its code is checked.
     *
     * @return void
     */
    public function testATotpSubmissionAgainstALockedFactor(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['consecutive_failures' => 5, 'locked_until' => now()->addHour()]);
        $code   = AuthenticatorApp::code($factor);

        // Reads (6): the factor found (1); the admission's factors, first
        // factor and state (5).
        //
        // Writes (4): the address's slot taken (2) and given back (1); the lock
        // (1). The code is never checked, so nothing is counted or proved.
        $result = $this->assertQueryBudget(6, 4, fn (): VerificationResult => $this->mfa()->verify(Submission::factor($factor->id, $code)));

        self::assertSame(FailureReason::LOCKED, $result->reason);
    }

    /**
     * Sending a code through the package's own challenge gateway.
     *
     * @return void
     */
    public function testADeliveredCodeSend(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        // Reads (15): the factor found (1); the request's factors, first
        // factor and state (5); the gateway's admission, the same again (5);
        // the send's factors (1); the factor's open code, and the destination's
        // and the identity's codes for their caps (3).
        //
        // Writes (7): the address's slot (2) and the slot given back (1); the
        // three locks (3); the code (1).
        $result = $this->assertQueryBudget(15, 7, fn () => $this->mfa()->sendCode($factor->id));

        self::assertTrue($result->wasSent());
    }

    /**
     * A delivered code accepted, in the window its send began.
     *
     * @return void
     */
    public function testADeliveredCodeHit(): void
    {
        $user = $this->signedInPerson();

        [$challenge, $code, $factor] = $this->sentTo($user);

        // Reads (19): the factor found (1); the admission's factors, first
        // factor and state (5); the gateway's admission, the same again (5);
        // the code (1); the report's factors and state (2); the proof's
        // generation (1); the evaluation's proofs, declaration and trust (3);
        // the re-enrolment obligation (1).
        //
        // Writes (8): the address's slot, by the update alone (1); the locks of
        // the admission, the gateway's admission and the report (3); the code's
        // attempt counted and its use (2); the factor's last use (1); and the
        // slot given back (1).
        $result = $this->assertQueryBudget(19, 8, fn (): VerificationResult => $this->mfa()->verify(Submission::challenge($factor, $challenge, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * A wrong delivered code counts on the code, in the identity's window and
     * in both runs.
     *
     * @return void
     */
    public function testADeliveredCodeMiss(): void
    {
        $user = $this->signedInPerson();

        [$challenge, $code, $factor] = $this->sentTo($user);

        $wrong = $code === '000000' ? '111111' : '000000';

        // Reads (15): as a hit, up to and including the report's factors and
        // state (14), and the identity's window read back (1).
        //
        // Writes (8): the address's slot (1); the three locks (3); the code's
        // attempt counted (1); the identity's window counted, and the
        // identity's and the factor's runs (3).
        $result = $this->assertQueryBudget(15, 8, fn (): VerificationResult => $this->mfa()->verify(Submission::challenge($factor, $challenge, $wrong)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
    }

    /**
     * The sets a redemption reads, by how many of the ten codes are used.
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
     * A recovery code accepted: the statements are the same however many of the
     * set are unused, and only the hashing follows that count.
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

        // Reads (14): the admission's factors and whether one is confirmed (2);
        // its first factor (3); the attempt's factors and state (2); the
        // redemption's state and unused codes (2); the proof's generation (1);
        // the evaluation's proofs, declaration and trust (3); the re-enrolment
        // obligation (1).
        //
        // Writes (6): the address's slot (2) and the slot given back (1); the
        // two locks (2); the code's use (1).
        $result = $this->assertQueryBudget(14, 6, fn (): VerificationResult => $this->mfa()->verify(Submission::recoveryCode($code)));

        self::assertTrue($result->isVerified());
        self::assertSame(10 - $used, $hasher->checks());
    }

    /**
     * A wrong recovery code costs the same statements at any size of the set.
     *
     * @param  int  $used
     * @return void
     */
    #[DataProvider('recoverySets')]
    public function testARecoveryCodeMiss(int $used): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $hasher = $this->usingSomeOfTheSet($this->recoveryCode($user), $used);

        // Reads (10): the admission's factors and whether one is confirmed (2);
        // its first factor (3); the attempt's factors and state (2); the
        // redemption's state and unused codes (2); the identity's window read
        // back (1).
        //
        // Writes (6): the address's slot (2); the two locks (2); the identity's
        // window counted and its run (2). No factor has failed, so no factor's
        // run; the slot is kept.
        $result = $this->assertQueryBudget(10, 6, fn (): VerificationResult => $this->mfa()->verify(Submission::recoveryCode(self::NO_RECOVERY_CODE)));

        self::assertSame(FailureReason::INVALID_CODE, $result->reason);
        self::assertSame(10 - $used, $hasher->checks());
    }

    /**
     * A passkey's assertion accepted, through a fake gateway.
     *
     * @return void
     */
    public function testAPasskeyHit(): void
    {
        $this->enablePasskeys();

        $user   = $this->signedInPerson();
        $factor = $this->passkeyFactor($user);

        // Reads (17): the factor found (1); the admission's factors, first
        // factor and state (5); the attempt's factors and state (2); the
        // association (1); the first factor read again for the assertion's
        // channel check (3); the proof's generation (1); the evaluation's
        // proofs, declaration and trust (3); the re-enrolment obligation (1).
        //
        // Writes (6): the address's slot (2) and the slot given back (1); the
        // two locks (2); the factor's last use (1). The gateway's own
        // statements are the adapter's, outside this budget.
        $result = $this->assertQueryBudget(17, 6, fn (): VerificationResult => $this->mfa()->verify(Submission::assertion($factor->id, ['id' => self::CREDENTIAL])));

        self::assertTrue($result->isVerified());
    }

    /**
     * A TOTP code accepted on a pending session, whose first factor and proofs
     * come from the pending context rather than the store.
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

        // Reads (7): the factor found (1); the admission's factors, whether its
        // first factor is trusted, and state (3); the attempt's factors and
        // state (2); the proof's generation (1).
        //
        // Writes (7): as a hit on an active session. What an adapter's
        // completion does with the proof is the adapter's, outside this budget.
        $result = $this->assertQueryBudget(7, 7, fn (): VerificationResult => $this->mfa()->verify(Submission::factor($factor->id, $code)));

        self::assertTrue($result->isVerified());
    }

    /**
     * Send the person's new email factor a code, and return the challenge, the
     * code and the factor.
     *
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
     * Mark the given number of the set's codes used, never the one given, and
     * count the hasher's checks from here on.
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
