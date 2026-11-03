<?php

declare(strict_types = 1);

namespace Tests\Feature\Verification;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\ChallengeRequests;
use SineMacula\Laravel\Mfa\Verification\CheckOutcome;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\SubmissionRoutes;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Http\InterruptingRequest;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\RecoveryCodes\CountingHasher;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Seams\ScriptedChallengeGateway;
use Tests\Fixtures\Verification\Concerns\ArrangesVerification;
use Tests\TestCase;

/**
 * Every way a verification fails has its machine-readable reason, one report,
 * and is counted or not as it should be; what a caller may be told stays within
 * the disclosure boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(VerificationService::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(SubmissionRoutes::class)]
#[CoversClass(CheckOutcome::class)]
#[CoversClass(VerificationResult::class)]
#[CoversClass(PasskeyAssertions::class)]
#[CoversClass(ChallengeOutcome::class)]
#[CoversClass(ChallengeRequests::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(SendResult::class)]
final class FailureReasonsVerificationServiceTest extends TestCase
{
    use ArrangesVerification;

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
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Without an MFA-capable person, nothing is served and nothing reported.
     *
     * @return void
     */
    public function testAGuestIsNotFound(): void
    {
        $result = $this->mfa()->verify(Submission::recoveryCode('ABCDEFGHJKLM'));

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame([], $this->reported);
    }

    /**
     * A factor that does not exist and one that belongs to someone else get the
     * same answer and the same report.
     *
     * @return void
     */
    public function testAMissingAndAForeignFactorAreIndistinguishable(): void
    {
        $other   = $this->person('other@example.test');
        $foreign = $this->totpFactor($other);
        $user    = $this->signedInPerson();

        $missing = $this->mfa()->verify(Submission::factor('01HZZZZZZZZZZZZZZZZZZZZZZZ', '000000'));
        $event   = $this->failureReported();

        $this->forgetReports();

        $found = $this->mfa()->verify(Submission::factor($foreign->id, '000000'));

        self::assertSame(FailureReason::NOT_FOUND, $missing->reason);
        self::assertEquals($missing, $found);
        self::assertEquals($event, $this->failureReported());
        self::assertNull($event->factor);
        self::assertNull($event->type);
        self::assertNull($event->challengeId);
        self::assertSame(0, $this->factorRun($foreign));
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * An id that is neither a string nor an integer finds nothing.
     *
     * @return void
     */
    public function testAnUnusableIdIsNotFound(): void
    {
        $this->signedInPerson();

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::factor(['1'], '000000'))->reason);
    }

    /**
     * A factor removed while the lock was awaited is reported as one that never
     * existed.
     *
     * @return void
     */
    public function testAFactorVanishedUnderTheLockIsNotFound(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $request = InterruptingRequest::create('/', 'POST');

        $request->interruption = static function () use ($factor): void {
            Factor::query()->whereKey($factor->id)->delete();
        };

        $this->container()->instance('request', $request);

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));
        $event  = $this->failureReported();

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertNull($event->factor);
        self::assertNull($event->type);
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * An inactive identity is refused, reported and counted nowhere.
     *
     * @return void
     */
    public function testAnInactiveIdentityIsRefused(): void
    {
        $identity = new NonEloquentIdentity(active: false);

        $this->actingAs($identity);

        $this->container()->make(ProofStore::class)->begin($identity, self::APPLICATION, self::SESSION);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->verify(Submission::factor('any', '000000'))->reason);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->failureReported()->reason);

        $this->forgetReports();

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->mfa()->verify(Submission::recoveryCode('ABCDEFGHJKLM'))->reason);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->failureReported()->reason);
    }

    /**
     * A factor still being enrolled is not confirmed.
     *
     * @return void
     */
    public function testAPendingFactorIsNotConfirmed(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['status' => 'pending', 'confirmed_at' => null]);

        self::assertSame(FailureReason::NOT_CONFIRMED, $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(FailureReason::NOT_CONFIRMED, $this->failureReported()->reason);
        self::assertSame(0, $this->factorRun($factor));
    }

    /**
     * A type the application does not enable is refused on every route, with
     * nothing sent, checked or counted.
     *
     * @return void
     */
    public function testATypeOffIsRefusedOnEveryRoute(): void
    {
        $user  = $this->signedInPerson();
        $totp  = $this->totpFactor($user);
        $email = $this->emailFactor($user);
        $code  = $this->recoveryCode($user);

        [$challenge, $emailed] = $this->sentCode($email);

        $this->enableApplication(['types' => [], 'recovery_codes' => ['enabled' => false]]);

        $this->forgetReports();

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->verify(Submission::factor($totp->id, AuthenticatorApp::code($totp)))->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->verify(Submission::challenge($email->id, $challenge, $emailed))->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->verify(Submission::recoveryCode($code))->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->sendCode($email->id)->reason);

        self::assertCount(3, $this->reported);
        self::assertSame(0, $this->factorRun($totp));
        self::assertSame(0, $this->factorRun($email));
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * A type turned off after the first check is refused under the lock, on the
     * factor as stored.
     *
     * @return void
     */
    public function testATypeOffUnderTheLockIsRefused(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        $request = InterruptingRequest::create('/', 'POST');

        $request->interruption = function (): void {
            $this->enableApplication(['types' => ['email']]);
        };

        $this->container()->instance('request', $request);

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);
        self::assertSame(0, $this->factorRun($factor));
        self::assertSame('totp', $this->failureReported()->type);
    }

    /**
     * A factor the combination policy does not accept after the first factor is
     * refused, and with no first factor known nothing is accepted.
     *
     * @return void
     */
    public function testAFactorNotAcceptedIsRefused(): void
    {
        $this->enableApplication(['first_factor' => ['method' => 'email', 'channel' => 'email']]);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->sendCode($factor->id)->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Submission::challenge($factor->id, 'any', '000000'))->reason);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->failureReported()->reason);
        self::assertSame(0, $this->factorRun($factor));
    }

    /**
     * A recovery code with no first factor known is refused before any hash is
     * checked.
     *
     * @return void
     */
    public function testARecoveryCodeWithNoFirstFactorIsRefused(): void
    {
        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(null));

        $this->enableApplication(['first_factor' => null]);

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = $this->recoveryCode($user);

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->reason);

        $this->forgetReports();

        $hasher = new CountingHasher($this->container()->make(Hasher::class));

        $this->container()->instance(Hasher::class, $hasher);

        $result = $this->mfa()->verify(Submission::recoveryCode($code));

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertSame(0, $hasher->checks());
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->failureReported()->reason);
        self::assertSame(0, $this->identityRun($user));
        self::assertSame(10, $this->mfa()->recoveryCodeStatus()?->remaining);
    }

    /**
     * The purposes refused, and whether on a pending session.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Mfa\Enums\Purpose, 1: bool}>
     */
    public static function refusedPurposes(): iterable
    {
        yield from [
            'an enrolment, active'        => [Purpose::ENROLLMENT, false],
            'a reauthentication, active'  => [Purpose::REAUTHENTICATE, false],
            'an enrolment, pending'       => [Purpose::ENROLLMENT, true],
            'a reauthentication, pending' => [Purpose::REAUTHENTICATE, true],
            'a step-up, pending'          => [Purpose::STEP_UP, true],
        ];
    }

    /**
     * Purposes a verification is not made for are refused, spending nothing.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  bool  $pending
     * @return void
     */
    #[DataProvider('refusedPurposes')]
    public function testARefusedPurposeSpendsNothing(?Purpose $purpose, bool $pending): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        if ($pending) {
            $this->pendingSession($user);
        }

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)), $purpose);

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertSame($purpose, $this->failureReported()->purpose);
        self::assertSame(FailureReason::NOT_ACCEPTED, $this->mfa()->sendCode($factor->id, $purpose)->reason);
        self::assertNull(Factor::query()->whereKey($factor->id)->sole()->getLastAcceptedStep());
    }

    /**
     * A recovery code never confirms an enrolment.
     *
     * @return void
     */
    public function testARecoveryCodeForAnEnrollmentIsNotAccepted(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $code   = $this->recoveryCode($user);
        $result = $this->mfa()->verify(Submission::recoveryCode($code), Purpose::ENROLLMENT);

        self::assertSame(FailureReason::NOT_ACCEPTED, $result->reason);
        self::assertSame(10, $this->mfa()->recoveryCodeStatus()?->remaining);
    }

    /**
     * A factor's lockout refuses it with the time it lifts, counting nothing.
     *
     * @return void
     */
    public function testATimedLockoutCarriesItsTime(): void
    {
        $user   = $this->signedInPerson();
        $until  = CarbonImmutable::now()->addHour();
        $factor = $this->totpFactor($user, ['consecutive_failures' => 5, 'locked_until' => $until]);

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame($until->getTimestamp(), $result->lockedUntil?->getTimestamp());
        self::assertSame(5, $this->factorRun($factor));
        self::assertSame(FailureReason::LOCKED, $this->failureReported()->reason);
    }

    /**
     * A factor disabled at the failure ceiling is locked with no time, since it
     * does not lift by itself, and a failure that reaches the ceiling is a
     * plain failure.
     *
     * @return void
     */
    public function testAFactorAtTheCeilingIsLockedWithNoTime(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user, ['disabled_at' => CarbonImmutable::now()]);

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertNull($result->lockedUntil);
        self::assertSame(FailureReason::LOCKED, $this->failureReported()->reason);
    }

    /**
     * An identity's run at the ceiling blocks recovery codes with no time,
     * while a usable factor can still recover the identity.
     *
     * @return void
     */
    public function testAnIdentityAtTheCeilingBlocksRecoveryCodesOnly(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);
        $code   = $this->recoveryCode($user);

        IdentityState::query()->where('authenticatable_id', (string) $user->id)->update(['consecutive_failures' => 100]);

        $result = $this->mfa()->verify(Submission::recoveryCode($code));

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertNull($result->lockedUntil);
        self::assertSame(FailureReason::LOCKED, $this->failureReported()->reason);
        self::assertSame('recovery_code', $this->failureReported()->type);
        self::assertSame(10, $this->mfa()->recoveryCodeStatus()?->remaining);

        self::assertTrue($this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * A recovery code refused by the identity's lockout says why in the
     * lockout's own words, timed or at the ceiling, not in a generic refusal.
     *
     * @return void
     */
    public function testARecoveryCodeRefusedByALockoutSaysWhy(): void
    {
        $user = $this->signedInPerson();

        $this->totpFactor($user);

        $code = $this->recoveryCode($user);

        IdentityState::query()->where('authenticatable_id', (string) $user->id)->update(['consecutive_failures' => 100]);

        self::assertSame(
            'The identity has reached the failure ceiling across its factors and recovery codes.',
            $this->mfa()->verify(Submission::recoveryCode($code))->detail,
        );

        IdentityState::query()->where('authenticatable_id', (string) $user->id)->update([
            'consecutive_failures' => 1,
            'locked_until'         => CarbonImmutable::now()->addMinutes(15),
        ]);

        self::assertSame(
            'The identity is locked after too many failed attempts across its factors.',
            $this->mfa()->verify(Submission::recoveryCode($code))->detail,
        );
    }

    /**
     * An address at its limit is refused with the time its window ends, before
     * anything else runs, and is reported with what was tried.
     *
     * @return void
     */
    public function testAThrottledAddressCarriesItsTime(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->requestFrom('203.0.113.9');

        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::factor($factor->id, '000000'))->reason);

        $this->forgetReports();

        $result = $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)));
        $event  = $this->failureReported();

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame(CarbonImmutable::now()->addSeconds(900)->getTimestamp(), $result->lockedUntil?->getTimestamp());
        self::assertSame($factor->id, $event->factor?->id);
        self::assertSame(1, $this->factorRun($factor));
        self::assertSame(FailureReason::LOCKED, $this->mfa()->sendCode($this->emailFactor($user)->id)->reason);
        self::assertSame(1, $this->addressHits('203.0.113.9'));
    }

    /**
     * A recovery code for an identity with no confirmed factor is refused, and
     * counted nowhere.
     *
     * @return void
     */
    public function testARecoveryCodeWithNoFactorIsRefused(): void
    {
        $user = $this->signedInPerson();

        self::assertSame(FailureReason::NO_FACTOR, $this->mfa()->verify(Submission::recoveryCode('ABCDEFGHJKLM'))->reason);
        self::assertSame(FailureReason::NO_FACTOR, $this->failureReported()->reason);
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * A wrong code is an invalid code on every route, and counted once.
     *
     * @return void
     */
    public function testAWrongCodeIsInvalidAndCounted(): void
    {
        $this->enablePasskeys(FailureReason::INVALID_CODE);

        $user  = $this->signedInPerson();
        $totp  = $this->totpFactor($user);
        $email = $this->emailFactor($user);
        $key   = $this->passkeyFactor($user);

        [$challenge] = $this->sentCode($email);

        $this->forgetReports();

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::factor($totp->id, 'x'))->reason);
        self::assertSame(1, $this->factorRun($totp));

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::challenge($email->id, $challenge, 'x'))->reason);
        self::assertSame(1, $this->factorRun($email));

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::assertion($key->id, ['id' => self::CREDENTIAL]))->reason);
        self::assertSame(1, $this->factorRun($key));

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::recoveryCode('ABCDEFGHJKLM'))->reason);

        self::assertSame(4, $this->identityRun($user));
        self::assertCount(4, $this->reported);
    }

    /**
     * A used or expired challenge is expired, and counted.
     *
     * @return void
     */
    public function testAnExpiredOrSpentChallengeIsExpiredAndCounted(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertTrue($this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code))->isVerified());

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->verify(Submission::challenge($factor->id, $challenge, 'other'))->reason);
        self::assertSame(1, $this->factorRun($factor));

        [$next] = $this->sentCode($factor);

        Carbon::setTestNow(CarbonImmutable::now()->addHour());

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->verify(Submission::challenge($factor->id, $next, 'other'))->reason);
        self::assertSame(2, $this->factorRun($factor));
    }

    /**
     * A challenge whose attempts are used up is expired, and counted.
     *
     * @return void
     */
    public function testAChallengeOutOfAttemptsIsExpiredAndCounted(): void
    {
        config()->set('mfa.codes.max_attempts', 1);

        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);

        [$challenge, $code] = $this->sentCode($factor);

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::challenge($factor->id, $challenge, 'wrong'))->reason);
        self::assertSame(FailureReason::EXPIRED, $this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code))->reason);
        self::assertSame(2, $this->factorRun($factor));
    }

    /**
     * A used code, a used TOTP step and a replayed assertion are all replayed,
     * and counted; a wrong TOTP code stays invalid.
     *
     * @return void
     */
    public function testAReplayIsReplayedAndCounted(): void
    {
        $this->enablePasskeys();

        $user  = $this->signedInPerson();
        $email = $this->emailFactor($user);
        $totp  = $this->totpFactor($user);
        $key   = $this->passkeyFactor($user);

        [$challenge, $code] = $this->sentCode($email);

        self::assertTrue($this->mfa()->verify(Submission::challenge($email->id, $challenge, $code))->isVerified());
        self::assertSame(FailureReason::REPLAYED, $this->mfa()->verify(Submission::challenge($email->id, $challenge, $code))->reason);
        self::assertSame(1, $this->factorRun($email));

        $step = AuthenticatorApp::code($totp);

        self::assertTrue($this->mfa()->verify(Submission::factor($totp->id, $step))->isVerified());
        self::assertSame(FailureReason::REPLAYED, $this->mfa()->verify(Submission::factor($totp->id, $step))->reason);
        self::assertSame(1, $this->factorRun($totp));

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::factor($totp->id, 'wrong'))->reason);

        $this->container()->instance(PasskeyGateway::class, $this->enablePasskeys(FailureReason::REPLAYED));

        self::assertSame(FailureReason::REPLAYED, $this->mfa()->verify(Submission::assertion($key->id, ['id' => self::CREDENTIAL]))->reason);
        self::assertSame(1, $this->factorRun($key));
    }

    /**
     * A TOTP code whose step comes before one already accepted is replayed, not
     * wrong.
     *
     * @return void
     */
    public function testAMatchedStepAfterALaterOneIsReplayed(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->totpFactor($user);

        self::assertTrue($this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor)))->isVerified());
        self::assertSame(FailureReason::REPLAYED, $this->mfa()->verify(Submission::factor($factor->id, AuthenticatorApp::code($factor, -1)))->reason);
    }

    /**
     * A challenge that is not the factor's is not found, and counted, so it
     * cannot be used to guess without paying for it.
     *
     * @return void
     */
    public function testAnUnknownChallengeIsNotFoundAndCounted(): void
    {
        $user    = $this->signedInPerson();
        $factor  = $this->emailFactor($user);
        $another = $this->emailFactor($user, 'another@example.test');

        [$challenge, $code] = $this->sentCode($another);

        $this->forgetReports();

        $result = $this->mfa()->verify(Submission::challenge($factor->id, $challenge, $code));
        $event  = $this->failureReported();

        self::assertSame(FailureReason::NOT_FOUND, $result->reason);
        self::assertSame(1, $this->factorRun($factor));
        self::assertSame($factor->id, $event->factor?->id);
        self::assertSame($challenge, $event->challengeId);
    }

    /**
     * A submission of the wrong kind for its factor is not found, with nothing
     * checked or counted.
     *
     * @return void
     */
    public function testASubmissionOfTheWrongKindIsNotFound(): void
    {
        $this->enablePasskeys();

        $user  = $this->signedInPerson();
        $email = $this->emailFactor($user);
        $totp  = $this->totpFactor($user);
        $key   = $this->passkeyFactor($user);

        $submissions = [
            Submission::factor($email->id, '000000'),
            Submission::assertion($email->id, []),
            Submission::challenge($totp->id, 'any', '000000'),
            Submission::assertion($totp->id, []),
            Submission::factor($key->id, '000000'),
            Submission::challenge($key->id, 'any', '000000'),
        ];

        foreach ($submissions as $submission) {
            self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify($submission)->reason);
        }

        self::assertCount(6, $this->reported);
        self::assertContainsOnlyInstancesOf(VerificationFailed::class, $this->reported);
        self::assertSame($email->id, $this->reported[0]->factor?->id);
        self::assertSame('email', $this->reported[0]->type);
        self::assertSame(0, $this->factorRun($email) + $this->factorRun($totp) + $this->factorRun($key));
        self::assertSame(0, $this->identityRun($user));
        self::assertSame(0, $this->addressHits('127.0.0.1'));
    }

    /**
     * A passkey's credential the gateway no longer lists is not found, and one
     * of the wrong credential is an invalid code; neither reaches a proof.
     *
     * @return void
     */
    public function testAPasskeysCeremonyChecksHoldUnderTheLock(): void
    {
        $gateway = $this->enablePasskeys();
        $user    = $this->signedInPerson();
        $factor  = $this->passkeyFactor($user);

        $gateway->registered = [];

        self::assertSame(FailureReason::NOT_FOUND, $this->mfa()->verify(Submission::assertion($factor->id, ['id' => self::CREDENTIAL]))->reason);
        self::assertSame(0, $this->factorRun($factor));

        $gateway->registered = [self::CREDENTIAL];
        $gateway->assertion  = new PasskeyAssertion('b3RoZXI', ObservedProperties::none());

        self::assertSame(FailureReason::INVALID_CODE, $this->mfa()->verify(Submission::assertion($factor->id, ['id' => self::CREDENTIAL]))->reason);
        self::assertSame(1, $this->factorRun($factor));
        self::assertSame([], $this->furtherProofs($user));
    }

    /**
     * A gateway that cannot verify at all refuses, counting nothing.
     *
     * @return void
     */
    public function testAnUnavailableGatewayCountsNothing(): void
    {
        $gateway = $this->enablePasskeys();
        $user    = $this->signedInPerson();
        $factor  = $this->passkeyFactor($user);

        try {
            $binding = new ProofBinding('user', '1', self::APPLICATION, self::SESSION, Purpose::STEP_UP);

            (new UnavailablePasskeyGateway)->verifyAssertion($user, $binding, [self::CREDENTIAL], ['id' => self::CREDENTIAL]);

            self::fail('The default gateway must refuse.');
        } catch (OperationRefusedException $exception) {
            $gateway->refusal = $exception;
        }

        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->mfa()->verify(Submission::assertion($factor->id, ['id' => self::CREDENTIAL]))->reason);
        self::assertSame(FailureReason::TYPE_NOT_ENABLED, $this->failureReported()->reason);
        self::assertSame(0, $this->factorRun($factor));
        self::assertSame(0, $this->identityRun($user));
    }

    /**
     * What an adapter's gateway says of a challenge is what is answered, and
     * one it refuses is counted nowhere and gives back the address's slot.
     *
     * @return void
     */
    public function testAGatewaysRefusalIsAnswered(): void
    {
        $user   = $this->signedInPerson();
        $factor = $this->emailFactor($user);
        $until  = CarbonImmutable::now()->addMinute();

        $this->requestFrom('203.0.113.9');

        $refusing = new ScriptedChallengeGateway(static fn (): ChallengeOutcome => ChallengeOutcome::refused(FailureReason::LOCKED, 'The challenge is locked.', $until));

        $this->container()->instance(ChallengeGateway::class, $refusing);

        $result = $this->mfa()->verify(Submission::challenge($factor->id, 'any', '000000'));

        self::assertSame(FailureReason::LOCKED, $result->reason);
        self::assertSame('The challenge is locked.', $result->detail);
        self::assertSame($until->getTimestamp(), $result->lockedUntil?->getTimestamp());
        self::assertSame(0, $this->addressHits('203.0.113.9'));

        $failing = new ScriptedChallengeGateway(static fn (): ChallengeOutcome => ChallengeOutcome::failed(FailureReason::EXPIRED, 'The challenge ended.'));

        $this->container()->instance(ChallengeGateway::class, $failing);

        self::assertSame(FailureReason::EXPIRED, $this->mfa()->verify(Submission::challenge($factor->id, 'any', '000000'))->reason);
        self::assertSame(1, $this->addressHits('203.0.113.9'));
    }
}
