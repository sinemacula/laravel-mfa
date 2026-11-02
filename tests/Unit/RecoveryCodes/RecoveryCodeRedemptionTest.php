<?php

declare(strict_types = 1);

namespace Tests\Unit\RecoveryCodes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Events\RecoveryCodesLow;
use SineMacula\Laravel\Mfa\Events\RecoveryCodeUsed;
use SineMacula\Laravel\Mfa\Events\VerificationFailed;
use SineMacula\Laravel\Mfa\Events\VerificationPassed;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Models\RecoveryCode;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeMatcher;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\RecoveryCodes\Redemption;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use SineMacula\Laravel\Mfa\Verification\VerificationService;
use Tests\Fixtures\Exceptions\MidRotationFailureException;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\RecoveryCodes\CountingHasher;
use Tests\TestCase;
use Tests\Unit\Concerns\InteractsWithRecoveryCodes;

/**
 * Tests for redeeming a recovery code: one attempt, and one event, against the
 * identity's whole unused set, with the same work whichever code matches and
 * whether one does; the submitted code normalised for case, spaces and hyphens;
 * a code used once only, also by two redemptions racing for it; the refusals
 * made before any attempt; the lockouts and counts of the attempt service; and
 * the events a redemption leaves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecoveryCodeService::class)]
#[CoversClass(Redemption::class)]
final class RecoveryCodeRedemptionTest extends TestCase
{
    use InteractsWithRecoveryCodes;

    /**
     * A code redeems once: it is marked used and the remaining count falls; the
     * same code then fails. The service records no proof of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeRedeemsOnce(): void
    {
        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder));

        $first = $this->recoveryCodes()->redeem($holder, $codes[4], self::bound($holder, Purpose::STEP_UP));

        self::assertTrue($first->passed);
        self::assertTrue($first->counted);
        self::assertSame(9, $first->remaining);
        self::assertNull($first->reason);
        self::assertCount(1, $this->storedCodes($holder)->filter(static fn (RecoveryCode $row): bool => $row->getUsedAt() !== null));
        self::assertSame([], $this->container()->make(ProofService::class)->proofs());

        $second = $this->recoveryCodes()->redeem($holder, $codes[4], self::bound($holder, Purpose::STEP_UP));

        self::assertFalse($second->passed);
        self::assertTrue($second->counted);
        self::assertSame(FailureReason::INVALID_CODE, $second->reason);
        self::assertSame(9, $second->remaining);
    }

    /**
     * Ways a person may type a code.
     *
     * @return iterable<string, array{\Closure(string): string}>
     */
    public static function typings(): iterable
    {
        yield 'lower case' => [static fn (string $code): string => strtolower($code)];
        yield 'grouped with hyphens' => [static fn (string $code): string => implode('-', str_split($code, 4))];
        yield 'grouped with spaces' => [static fn (string $code): string => ' ' . implode(' ', str_split(strtolower($code), 4)) . ' '];
        yield 'with tabs and line breaks' => [static fn (string $code): string => "\t" . substr($code, 0, 6) . "\r\n" . substr($code, 6) . "\n"];
    }

    /**
     * A code typed in lower case, grouped with hyphens or spaces, or broken
     * over lines redeems.
     *
     * @param  \Closure(string): string  $typed
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('typings')]
    public function testNormalizesCaseSpacesAndHyphens(\Closure $typed): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        self::assertTrue($this->recoveryCodes()->redeem($holder, $typed($code), self::bound($holder, Purpose::SIGN_IN))->passed);
    }

    /**
     * Every redemption checks every unused code of the set, whichever code
     * matches, when none does and when the code is malformed: the work grows
     * with the unused count only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheWorkIsTheSameWhicheverCodeMatches(): void
    {
        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder));
        $hasher = $this->countChecks();

        foreach ($codes as $index => $code) {

            $before = $hasher->checks();

            self::assertTrue($this->recoveryCodes()->redeem($holder, $code, self::bound($holder, Purpose::SIGN_IN))->passed);
            self::assertSame(10 - $index, $hasher->checks() - $before, 'Redeeming code ' . $index . ' checked a different number of codes.');

            if ($index !== 4) {
                continue;
            }

            $before = $hasher->checks();

            self::assertFalse($this->recoveryCodes()->redeem($holder, 'ZZZZZZZZZZZZ', self::bound($holder, Purpose::SIGN_IN))->passed);
            self::assertSame(5, $hasher->checks() - $before);

            $before = $hasher->checks();

            self::assertFalse($this->recoveryCodes()->redeem($holder, str_repeat('A', 300), self::bound($holder, Purpose::SIGN_IN))->passed);
            self::assertSame(5, $hasher->checks() - $before);
        }
    }

    /**
     * A malformed code is never rejected early: it is one counted attempt that
     * checks the placeholder against the whole set, and matches nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedCodeIsCheckedAgainstTheWholeSet(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder);

        $hasher     = $this->countChecks();
        $redemption = $this->recoveryCodes()->redeem($holder, str_repeat('ABCD-', 60), self::bound($holder, Purpose::SIGN_IN));

        self::assertFalse($redemption->passed);
        self::assertTrue($redemption->counted);
        self::assertSame(FailureReason::INVALID_CODE, $redemption->reason);
        self::assertSame(10, $redemption->remaining);
        self::assertSame(array_fill(0, 10, RecoveryCodeMatcher::PLACEHOLDER), $hasher->checked);
        self::assertSame(1, $this->stateOf($holder)->consecutive_failures);
    }

    /**
     * Without a set, or with every code used, a redemption is one counted
     * attempt that checks nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAnUnusedCodeNothingIsChecked(): void
    {
        $holder = $this->signInHolder();
        $hasher = $this->countChecks();

        $redemption = $this->recoveryCodes()->redeem($holder, 'ABCDEFGHJKLM', self::bound($holder, Purpose::SIGN_IN));

        self::assertFalse($redemption->passed);
        self::assertTrue($redemption->counted);
        self::assertSame(0, $redemption->remaining);
        self::assertSame(0, $hasher->checks());
        self::assertSame(1, $this->stateOf($holder)->consecutive_failures);
    }

    /**
     * A code of an earlier generation never redeems, even while it is marked
     * neither used nor replaced.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeOfAnotherGenerationNeverRedeems(): void
    {
        $holder = $this->signInHolder();

        $this->recoveryCodes()->generate($holder);
        $this->recoveryCodes()->generate($holder);

        RecoveryCode::query()->create([
            'authenticatable_type' => $holder->getMorphClass(),
            'authenticatable_id'   => (string) $holder->id,
            'code_hash'            => $this->container()->make(Hasher::class)->make('OLDGENERATION'),
            'generation'           => 1,
        ]);

        $redemption = $this->recoveryCodes()->redeem($holder, 'OLDGENERATION', self::bound($holder, Purpose::SIGN_IN));

        self::assertFalse($redemption->passed);
        self::assertSame(10, $redemption->remaining);
    }

    /**
     * A failure is counted against the identity, and a success resets its run
     * of failures.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureCountsAndASuccessResetsTheRun(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        $this->recoveryCodes()->redeem($holder, 'WRONGWRONG22', self::bound($holder, Purpose::SIGN_IN));
        $this->recoveryCodes()->redeem($holder, 'WRONGWRONG23', self::bound($holder, Purpose::SIGN_IN));

        self::assertSame(2, $this->stateOf($holder)->consecutive_failures);

        $this->recoveryCodes()->redeem($holder, $code, self::bound($holder, Purpose::SIGN_IN));

        self::assertSame(0, $this->stateOf($holder)->consecutive_failures);
    }

    /**
     * A failure is charged to the request's IP address too, so a further
     * attempt from it past its limit is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureIsChargedToTheAddress(): void
    {
        config()->set('mfa.attempts.ip_limit', 1);

        $this->container()->instance('request', Request::create('/mfa/recover', 'POST', server: ['REMOTE_ADDR' => '192.0.2.7']));

        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        self::assertSame(FailureReason::INVALID_CODE, $this->verify('WRONGWRONG22')->reason);

        $refused = $this->verify($code);

        self::assertSame(FailureReason::LOCKED, $refused->reason);
        self::assertNotNull($refused->lockedUntil);
    }

    /**
     * While the identity is locked out, a redemption is refused with the time
     * the lockout lifts, without checking a code or counting anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockoutRefusesWithoutCheckingAnything(): void
    {
        $this->travelTo(CarbonImmutable::parse('2026-11-01 12:00:00'));

        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $until  = CarbonImmutable::parse('2026-11-01 12:15:00');

        IdentityState::query()->where('authenticatable_id', (string) $holder->id)->update(['locked_until' => $until]);

        $hasher = $this->countChecks();

        $redemption = $this->recoveryCodes()->redeem($holder, $code, self::bound($holder, Purpose::SIGN_IN));

        self::assertFalse($redemption->passed);
        self::assertFalse($redemption->counted);
        self::assertSame(FailureReason::LOCKED, $redemption->reason);
        self::assertSame($until->getTimestamp(), $redemption->lockedUntil?->getTimestamp());
        self::assertNull($redemption->remaining);
        self::assertSame(0, $hasher->checks());
        self::assertSame(0, $this->stateOf($holder)->consecutive_failures);
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * An identity whose run of failures reached the failure ceiling is refused
     * as locked, with no time the lockout lifts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFailureCeilingRefusesWithoutATime(): void
    {
        config()->set('mfa.attempts.failure_ceiling', 1);

        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        $this->recoveryCodes()->redeem($holder, 'WRONGWRONG22', self::bound($holder, Purpose::SIGN_IN));

        $redemption = $this->recoveryCodes()->redeem($holder, $code, self::bound($holder, Purpose::SIGN_IN));

        self::assertFalse($redemption->passed);
        self::assertSame(FailureReason::LOCKED, $redemption->reason);
        self::assertNull($redemption->lockedUntil);
    }

    /**
     * A recovery code cannot confirm an enrolment: refused before the attempt,
     * so the code is not spent and nothing is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEnrollmentIsRefused(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $hasher = $this->countChecks();

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->verify($code, Purpose::ENROLLMENT)->reason);
        self::assertSame(0, $hasher->checks());
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * An application that does not accept recovery codes refuses them before
     * the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationThatDoesNotAcceptRecoveryCodesRefusesThem(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        config()->set('mfa.applications.web.recovery_codes.enabled', false);

        $this->assertRefusedRedemption($code, FailureReason::TYPE_NOT_ENABLED);
    }

    /**
     * An identity without a confirmed factor is refused before the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAConfirmedFactorIsRefused(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        Factor::query()->update(['status' => 'pending']);

        $this->assertRefusedRedemption($code, FailureReason::NO_FACTOR);
    }

    /**
     * An identity with no sign-in is served nothing, so a single-use code is
     * never spent for no proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutASignInIsRefused(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        $this->container()->make(ProofStore::class)->forget($holder, 'web');

        self::assertSame(FailureReason::NOT_FOUND, $this->verify($code)->reason);
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * A machine identity and an inactive one are not admitted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachineOrInactiveIdentityIsRefused(): void
    {
        $machine  = new NonEloquentIdentity('machine', mfaEnabled: true, person: false);
        $inactive = new NonEloquentIdentity('inactive', mfaEnabled: true, active: false);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $this->recoveryCodes()->admission($machine, self::bound($machine, Purpose::SIGN_IN))->reason);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->recoveryCodes()->admission($inactive, self::bound($inactive, Purpose::SIGN_IN))->reason);
    }

    /**
     * A success dispatches, once the use commits and in this order,
     * `VerificationPassed`, `RecoveryCodeUsed` with the remaining count and, at
     * or below the low count, `RecoveryCodesLow`: at the threshold, below it
     * and at zero.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessReportsTheUseAndALowSet(): void
    {
        config()->set('mfa.recovery_codes.count', 5);
        config()->set('mfa.recovery_codes.low_count', 3);

        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder));
        $seen   = $this->recordRedemptionEvents();

        foreach ($codes as $code) {
            $this->verify($code);
        }

        self::assertSame([
            'passed', 'used:4',
            'passed', 'used:3', 'low:3',
            'passed', 'used:2', 'low:2',
            'passed', 'used:1', 'low:1',
            'passed', 'used:0', 'low:0',
        ], $seen->getArrayCopy());
    }

    /**
     * With a low count of 0, no redemption reports a low set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALowCountOfZeroReportsNoLowSet(): void
    {
        config()->set('mfa.recovery_codes.count', 2);
        config()->set('mfa.recovery_codes.low_count', 0);

        $holder = $this->signInHolder();
        $codes  = self::plaintexts($this->recoveryCodes()->generate($holder));
        $seen   = $this->recordRedemptionEvents();

        foreach ($codes as $code) {
            $this->verify($code);
        }

        self::assertSame(['passed', 'used:1', 'passed', 'used:0'], $seen->getArrayCopy());
    }

    /**
     * The events carry the type, the purpose and the application, never the
     * code; a failure is one `VerificationFailed` and nothing else.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEventsCarryNoCode(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];

        Event::fake([VerificationPassed::class, VerificationFailed::class, RecoveryCodeUsed::class, RecoveryCodesLow::class]);

        $this->verify('WRONGWRONG22', Purpose::SIGN_IN);

        Event::assertDispatchedTimes(VerificationFailed::class, 1);
        Event::assertNotDispatched(VerificationPassed::class);
        Event::assertNotDispatched(RecoveryCodeUsed::class);
        Event::assertDispatched(VerificationFailed::class, static fn (VerificationFailed $event): bool => $event->factor === null
            && $event->type                                                                                              === RecoveryCodeService::TYPE
            && $event->purpose                                                                                           === Purpose::SIGN_IN
            && $event->reason                                                                                            === FailureReason::INVALID_CODE
            && $event->context['application']                                                                            === 'web');

        $this->verify($code);

        Event::assertDispatched(VerificationPassed::class, static fn (VerificationPassed $event): bool => $event->factor === null
            && $event->type                                                                                              === RecoveryCodeService::TYPE
            && $event->purpose                                                                                           === Purpose::STEP_UP
            && !str_contains((string) json_encode($event->context), $code));
        Event::assertDispatched(RecoveryCodeUsed::class, static fn (RecoveryCodeUsed $event): bool => $event->remaining === 9 && $event->purpose === Purpose::STEP_UP);
    }

    /**
     * A redemption inside a transaction on the storage connection that rolls
     * back leaves the code unused and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNothingIsReportedWhenTheSurroundingTransactionRollsBack(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $seen   = $this->recordRedemptionEvents();

        try {
            DB::connection()->transaction(function () use ($code): void {

                self::assertTrue($this->verify($code)->isVerified());

                throw new MidRotationFailureException('Rolled back.');
            });
        } catch (MidRotationFailureException $exception) {
            self::assertSame('Rolled back.', $exception->getMessage());
        }

        self::assertSame([], $seen->getArrayCopy());
        self::assertSame([], $this->container()->make(ProofService::class)->proofs());
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * Of two redemptions of one code, only one passes: one that read the set
     * before the other used the code finds, when it marks the code used, that
     * it no longer is unused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOfTwoRedemptionsOfOneCodeOnlyOnePasses(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $hasher = $this->countChecks();
        $winner = null;

        $hasher->before(function () use ($holder, $code, &$winner): void {
            $winner = $this->recoveryCodes()->redeem($holder, $code, self::bound($holder, Purpose::SIGN_IN));
        });

        $loser = $this->recoveryCodes()->redeem($holder, $code, self::bound($holder, Purpose::SIGN_IN));

        self::assertInstanceOf(Redemption::class, $winner);
        self::assertTrue($winner->passed);
        self::assertFalse($loser->passed);
        self::assertSame(FailureReason::INVALID_CODE, $loser->reason);
        self::assertCount(1, $this->storedCodes($holder)->filter(static fn (RecoveryCode $row): bool => $row->getUsedAt() !== null));
    }

    /**
     * A redemption that read the old set before a replacement ran finds its
     * code replaced and fails; the new set redeems.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionRacingAReplacementFindsTheOldSetReplaced(): void
    {
        $holder  = $this->signInHolder();
        $old     = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $hasher  = $this->countChecks();
        $current = null;

        $hasher->before(function () use ($holder, &$current): void {
            $current = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        });

        self::assertFalse($this->recoveryCodes()->redeem($holder, $old, self::bound($holder, Purpose::SIGN_IN))->passed);
        self::assertCount(0, $this->storedCodes($holder)->filter(static fn (RecoveryCode $row): bool => $row->getUsedAt() !== null));
        self::assertIsString($current);
        self::assertTrue($this->recoveryCodes()->redeem($holder, $current, self::bound($holder, Purpose::SIGN_IN))->passed);
    }

    /**
     * A redemption whose identity's last confirmed factor goes while it waits
     * for the lock is refused, checking and counting nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionRacingTheLastFactorsRemovalFails(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $hasher = $this->countChecks();

        $this->onceTheLockIsTaken(static function (): void {
            Factor::query()->delete();
        });

        self::assertSame(FailureReason::NO_FACTOR, $this->verify($code)->reason);
        self::assertSame(0, $hasher->checks());
        self::assertSame(0, $this->stateOf($holder)->consecutive_failures);
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * A redemption whose identity's sign-in ends while it waits for the lock is
     * refused as not found, checking and counting nothing, spending no code and
     * reporting nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionRacingTheEndOfTheSignInFails(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $hasher = $this->countChecks();
        $seen   = $this->recordRedemptionEvents();

        $this->onceTheLockIsTaken(static function (): void {
            Auth::logout();
        });

        self::assertSame(FailureReason::NOT_FOUND, $this->verify($code)->reason);
        self::assertSame(0, $hasher->checks());
        self::assertSame([], $seen->getArrayCopy());
        self::assertSame(0, $this->stateOf($holder)->consecutive_failures);
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * A redemption whose identity's sign-in ends while the code is being
     * checked has no first factor left to be accepted after: it is refused, so
     * the code's use rolls back and nothing is counted, rather than pass
     * without a proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionWhoseSignInEndsDuringTheCheckRecordsNothing(): void
    {
        $holder = $this->signInHolder();
        $code   = self::plaintexts($this->recoveryCodes()->generate($holder))[0];
        $hasher = $this->countChecks();
        $seen   = $this->recordRedemptionEvents();

        $hasher->before(static function (): void {
            Auth::logout();
        });

        self::assertSame(FailureReason::NOT_ACCEPTED, $this->verify($code)->reason);
        self::assertSame(10, $hasher->checks());
        self::assertSame(['failed'], $seen->getArrayCopy());
        self::assertSame(0, (int) DB::table('mfa_attempts')->sum('hits'));
        self::assertSame(0, (int) IdentityState::query()->sum('consecutive_failures'));
        self::assertTrue($this->storedCodes($holder)->every(static fn (RecoveryCode $row): bool => $row->isUsable()));
    }

    /**
     * Assert a redemption is refused before any attempt with the given reason:
     * nothing counted or checked, no code spent, and one `VerificationFailed`.
     *
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefusedRedemption(string $code, FailureReason $reason): void
    {
        $hasher = $this->countChecks();
        $failed = [];

        Event::listen(VerificationFailed::class, static function (VerificationFailed $event) use (&$failed): void {
            $failed[] = $event;
        });

        $result = $this->verify($code, Purpose::SIGN_IN);

        self::assertSame($reason, $result->reason);
        self::assertNull($result->lockedUntil);
        self::assertSame(0, $hasher->checks());
        self::assertSame(0, (int) DB::table('mfa_attempts')->sum('hits'));
        self::assertSame(0, (int) IdentityState::query()->sum('consecutive_failures'));
        self::assertSame(0, RecoveryCode::query()->whereNotNull('used_at')->count());
        self::assertCount(1, $failed);
        self::assertSame($reason, $failed[0]->reason);
        self::assertSame(Purpose::SIGN_IN, $failed[0]->purpose);
        self::assertSame(RecoveryCodeService::TYPE, $failed[0]->type);
    }

    /**
     * Submit the recovery code through the package's one way of verifying.
     *
     * @param  string  $code
     * @param  ?\SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Throwable
     */
    private function verify(#[\SensitiveParameter] string $code, ?Purpose $purpose = null): VerificationResult
    {
        return $this->container()->make(VerificationService::class)->verify(Submission::recoveryCode($code), $purpose);
    }

    /**
     * What a redemption by the identity is bound to.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function bound(MultiFactorAuthenticatable $identity, Purpose $purpose): ProofBinding
    {
        $owner = ProofOwner::of($identity);

        return new ProofBinding($owner->type, $owner->key, 'web', 'redemption-sign-in', $purpose);
    }

    /**
     * Count the hasher's checks from now on, handing each to the real hasher.
     *
     * @return \Tests\Fixtures\RecoveryCodes\CountingHasher
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function countChecks(): CountingHasher
    {
        $hasher = new CountingHasher($this->container()->make(Hasher::class));

        $this->container()->instance(Hasher::class, $hasher);

        return $hasher;
    }

    /**
     * Record the redemption events as they are dispatched: `passed`,
     * `used:{remaining}` and `low:{remaining}`.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordRedemptionEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $seen */
        $seen = new \ArrayObject;

        Event::listen(VerificationPassed::class, static function () use ($seen): void {
            $seen->append('passed');
        });

        Event::listen(RecoveryCodeUsed::class, static function (RecoveryCodeUsed $event) use ($seen): void {
            $seen->append('used:' . $event->remaining);
        });

        Event::listen(RecoveryCodesLow::class, static function (RecoveryCodesLow $event) use ($seen): void {
            $seen->append('low:' . $event->remaining);
        });

        Event::listen(VerificationFailed::class, static function () use ($seen): void {
            $seen->append('failed');
        });

        return $seen;
    }

    /**
     * Run the callback once, just after the identity's state lock is taken:
     * inside the lock, before the attempt's verification runs, as a change that
     * committed while the redemption waited for the lock.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function onceTheLockIsTaken(\Closure $callback): void
    {
        $done = false;

        DB::listen(static function (QueryExecuted $query) use ($callback, &$done): void {
            if ($done || !str_contains($query->sql, 'mfa_identity_states') || !str_starts_with(strtolower(ltrim($query->sql)), 'insert')) {
                return;
            }

            $done = true;

            $callback();
        });
    }
}
