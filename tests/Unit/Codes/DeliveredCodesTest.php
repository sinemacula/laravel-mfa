<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\DeliveredCodes;
use SineMacula\Laravel\Mfa\Codes\IssuedCode;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Code;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveredCodes::class)]
final class DeliveredCodesTest extends TestCase
{
    /** @var string The factor the codes are sent for. */
    private const string FACTOR = '01jfactor0000000000000000a1';

    /** @var string The destination the codes are sent to. */
    private const string DESTINATION = 'person@example.test';

    /** @var string The first code drawn. */
    private const string CODE = '123456';

    /** @var string The second code drawn. */
    private const string NEXT_CODE = '654321';

    /** @var string A code never drawn. */
    private const string WRONG_CODE = '000000';

    /** @var list<string> The codes the engine draws next, in order. */
    private array $draws = [];

    /**
     * Used, it is replayed for itself and missing for any other code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeIsAcceptedOnceForItsOwnBinding(): void
    {
        $codes  = $this->codes([], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(self::CODE, $issued->code);
        self::assertSame($now->addMinutes(10)->getTimestamp(), $issued->expiresAt->getTimestamp());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(CodeCheck::REPLAYED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(CodeCheck::SPENT, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId));
        self::assertNotNull(self::row($issued)->consumed_at);
    }

    /**
     * @return iterable<string, array{string, \SineMacula\Laravel\Mfa\Proofs\ProofBinding}>
     */
    public static function otherBindings(): iterable
    {
        yield 'another session' => [self::FACTOR, self::binding(session: 'session-b')];
        yield 'another purpose' => [self::FACTOR, self::binding(purpose: Purpose::STEP_UP)];
        yield 'another factor' => ['01jfactor0000000000000000b2', self::binding()];
        yield 'another application' => [self::FACTOR, self::binding(application: 'admin')];
        yield 'another identity' => [self::FACTOR, self::binding(identity: '2')];
    }

    /**
     * Such a check counts no attempt, so the code still works for its own
     * binding.
     *
     * @param  string  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('otherBindings')]
    public function testACodeMatchesNothingButItsOwnFactorAndBinding(string $factor, ProofBinding $binding): void
    {
        $codes  = $this->codes([], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(CodeCheck::MISSING, $codes->check($factor, $binding, self::CODE, $now, $issued->challengeId));
        self::assertSame(0, self::row($issued)->attempts);
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnUnknownChallengeIsMissing(): void
    {
        $codes = $this->codes([], [self::CODE]);
        $now   = self::now();

        $codes->issue(self::FACTOR, self::binding(), $now);

        self::assertSame(CodeCheck::MISSING, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, '01jnochallenge00000000000000'));
    }

    /**
     * The code is a keyed hash bound to its challenge and binding, and the
     * session a keyed digest.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeIsStoredOnlyAsAKeyedHash(): void
    {
        $codes  = $this->codes([], [self::CODE, self::CODE]);
        $now    = self::now();
        $first  = self::row(self::issued($codes->issue(self::FACTOR, self::binding(), $now)));
        $second = self::row(self::issued($codes->issue(self::FACTOR, self::binding(session: 'session-b'), $now)));

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $first->code_hash);
        self::assertNotSame(hash('sha256', self::CODE), $first->code_hash);
        self::assertNotSame($first->code_hash, $second->code_hash);
        self::assertNotSame('session-a', $first->session_id);
        self::assertNotSame($first->session_id, $second->session_id);
        self::assertSame(self::FACTOR, $first->factor_id);
        self::assertSame(TestUser::class, $first->authenticatable_type);
        self::assertSame('1', $first->authenticatable_id);
        self::assertSame('sign_in', $first->purpose);
        self::assertSame('web', $first->application);
        self::assertSame(1, $first->sends);
        self::assertSame([$now->getTimestamp()], $first->sent_times);
        self::assertSame(0, $first->attempts);
        self::assertNull($first->consumed_at);
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAWrongCodeIsInvalidAndCountsAnAttempt(): void
    {
        $codes  = $this->codes([], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId));
        self::assertSame(1, self::row($issued)->attempts);
        self::assertNull(self::row($issued)->consumed_at);
    }

    /**
     * Even the right code is refused, without counting another attempt.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAChallengeIsExhaustedAfterItsAttempts(): void
    {
        $codes  = $this->codes(['max_attempts' => 2], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId));
        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId));
        self::assertSame(CodeCheck::EXHAUSTED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(2, self::row($issued)->attempts);
    }

    /**
     * Refused from the second it expires, and works until then.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnExpiredCodeIsRefusedWithoutCountingAnAttempt(): void
    {
        $codes  = $this->codes(['ttl_minutes' => 5], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(CodeCheck::EXPIRED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now->addMinutes(5), $issued->challengeId));
        self::assertSame(0, self::row($issued)->attempts);
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now->addMinutes(5)->subSecond(), $issued->challengeId));
    }

    /**
     * Then it sends a new code for the same challenge.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendWaitsOutTheCooldown(): void
    {
        $codes = $this->codes(['resend_cooldown_seconds' => 60], [self::CODE, self::NEXT_CODE]);
        $now   = self::now();
        $first = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(60, $codes->issue(self::FACTOR, self::binding(), $now));
        self::assertSame(1, $codes->issue(self::FACTOR, self::binding(), $now->addSeconds(59)));

        $second = self::issued($codes->issue(self::FACTOR, self::binding(), $now->addSeconds(60)));

        self::assertSame($first->challengeId, $second->challengeId);
        self::assertSame(self::NEXT_CODE, $second->code);
        self::assertSame(2, self::row($second)->sends);
        self::assertSame(1, Code::query()->count());
    }

    /**
     * Only the new code works.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendReplacesThePreviousCode(): void
    {
        $codes = $this->codes([], [self::CODE, self::NEXT_CODE]);
        $now   = self::now()->addSeconds(60);

        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), self::now()));
        $codes->issue(self::FACTOR, self::binding(), $now);

        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), self::NEXT_CODE, $now, $issued->challengeId));
    }

    /**
     * The old digits would still match under the new issue, so it draws again
     * until they differ.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendNeverRepeatsThePreviousCode(): void
    {
        $codes = $this->codes([], [self::CODE, self::CODE, self::NEXT_CODE]);
        $now   = self::now()->addSeconds(60);

        $codes->issue(self::FACTOR, self::binding(), self::now());

        $resent = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(self::NEXT_CODE, $resent->code);
        self::assertSame([], $this->draws);
        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $resent->challengeId));
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), self::NEXT_CODE, $now, $resent->challengeId));
    }

    /**
     * A new code brings no new attempts.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendKeepsTheAttemptBudget(): void
    {
        $codes = $this->codes(['max_attempts' => 3], [self::CODE, self::NEXT_CODE]);
        $now   = self::now();

        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId));
        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId));

        $resent = self::issued($codes->issue(self::FACTOR, self::binding(), $now->addSeconds(60)));

        self::assertSame(2, self::row($resent)->attempts);
        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now->addSeconds(60), $resent->challengeId));
        self::assertSame(CodeCheck::EXHAUSTED, $codes->check(self::FACTOR, self::binding(), self::NEXT_CODE, $now->addSeconds(60), $resent->challengeId));
    }

    /**
     * Once the challenge has ended, the next code starts a new one.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendNeverOutlivesItsChallenge(): void
    {
        $codes = $this->codes(['ttl_minutes' => 10, 'challenge_ttl_minutes' => 12], [self::CODE, self::NEXT_CODE, '111111']);
        $now   = self::now();
        $first = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $resent = self::issued($codes->issue(self::FACTOR, self::binding(), $now->addMinutes(5)));

        self::assertSame($first->challengeId, $resent->challengeId);
        self::assertSame($now->addMinutes(12)->getTimestamp(), $resent->expiresAt->getTimestamp());
        self::assertSame(CodeCheck::EXPIRED, $codes->check(self::FACTOR, self::binding(), self::NEXT_CODE, $now->addMinutes(12), $resent->challengeId));

        $fresh = self::issued($codes->issue(self::FACTOR, self::binding(), $now->addMinutes(12)));

        self::assertNotSame($first->challengeId, $fresh->challengeId);
        self::assertSame($now->addMinutes(22)->getTimestamp(), $fresh->expiresAt->getTimestamp());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), '111111', $now->addMinutes(12), $fresh->challengeId));
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnExhaustedChallengeSendsNoMoreUntilItEnds(): void
    {
        $codes = $this->codes(['max_attempts' => 1, 'challenge_ttl_minutes' => 30], [self::CODE, self::NEXT_CODE]);
        $now   = self::now();

        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));
        $codes->check(self::FACTOR, self::binding(), self::WRONG_CODE, $now, $issued->challengeId);

        self::assertSame(1740, $codes->issue(self::FACTOR, self::binding(), $now->addSeconds(60)));
        self::assertInstanceOf(IssuedCode::class, $codes->issue(self::FACTOR, self::binding(), $now->addMinutes(30)));
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testANewChallengeStartsOnceTheLastWasUsed(): void
    {
        $codes = $this->codes([], [self::CODE, self::NEXT_CODE]);
        $now   = self::now();
        $first = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $first->challengeId);

        $second = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertNotSame($first->challengeId, $second->challengeId);
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), self::NEXT_CODE, $now, $second->challengeId));
    }

    /**
     * Across every session, until the oldest send leaves the window.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheFactorCapCountsSendsAcrossSessions(): void
    {
        $codes = $this->codes(['factor_send_limit' => 2, 'send_window_minutes' => 60], ['111111', '222222', '333333']);
        $now   = self::now();

        self::issued($codes->issue(self::FACTOR, self::binding(session: 'session-a'), $now));
        self::issued($codes->issue(self::FACTOR, self::binding(session: 'session-b'), $now->addSeconds(10)));

        self::assertSame(3580, $codes->issue(self::FACTOR, self::binding(session: 'session-c'), $now->addSeconds(20)));
        self::assertSame(1, $codes->issue(self::FACTOR, self::binding(session: 'session-c'), $now->addSeconds(3599)));
        self::assertInstanceOf(IssuedCode::class, $codes->issue(self::FACTOR, self::binding(session: 'session-c'), $now->addSeconds(3600)));
    }

    /**
     * Counted per destination, so a pending factor discarded for a new one
     * leaves its sends counted.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheFactorCapCountsADestinationAcrossItsFactors(): void
    {
        $codes = $this->codes(['factor_send_limit' => 1], ['111111', '222222', '333333', '444444', '555555', '666666']);
        $now   = self::now();

        self::issued($codes->issue(self::FACTOR, self::binding(), $now, self::DESTINATION));

        self::assertSame(3600, $codes->issue('another-factor', self::binding(session: 'session-b'), $now, self::DESTINATION));

        self::issued($codes->issue('another-factor', self::binding(session: 'session-b'), $now, 'other@example.test'));
        self::issued($codes->issue('another-factor', self::binding(session: 'session-c', identity: '2'), $now, self::DESTINATION));
        self::issued($codes->issue('third-factor', self::binding(session: 'session-b'), $now));

        self::assertSame(3600, $codes->issue('third-factor', self::binding(session: 'session-c'), $now));

        self::issued($codes->issue('fourth-factor', self::binding(session: 'session-c'), $now));
    }

    /**
     * Though its factor is new; other purposes and other destinations do not
     * wait.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testANewEnrollmentChallengeWaitsOutTheCooldownOfItsDestination(): void
    {
        $codes = $this->codes(['resend_cooldown_seconds' => 60], ['111111', '222222', '333333', '444444', '555555']);
        $now   = self::now();

        self::issued($codes->issue(self::FACTOR, self::binding(purpose: Purpose::ENROLLMENT), $now, self::DESTINATION));

        self::assertSame(50, $codes->issue('another-factor', self::binding(purpose: Purpose::ENROLLMENT), $now->addSeconds(10), self::DESTINATION));

        self::issued($codes->issue('another-factor', self::binding(), $now->addSeconds(10), self::DESTINATION));
        self::issued($codes->issue('third-factor', self::binding(purpose: Purpose::ENROLLMENT), $now->addSeconds(10), 'other@example.test'));

        self::assertSame(1, $codes->issue('another-factor', self::binding(purpose: Purpose::ENROLLMENT), $now->addSeconds(59), self::DESTINATION));

        self::issued($codes->issue('another-factor', self::binding(purpose: Purpose::ENROLLMENT), $now->addSeconds(60), self::DESTINATION));
    }

    /**
     * Another identity is unaffected.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheIdentityCapCountsSendsAcrossFactors(): void
    {
        $codes = $this->codes(['identity_send_limit' => 2], ['111111', '222222', '333333']);
        $now   = self::now();

        self::issued($codes->issue('01jfactor0000000000000000c1', self::binding(), $now));
        self::issued($codes->issue('01jfactor0000000000000000c2', self::binding(), $now));

        self::assertSame(3600, $codes->issue('01jfactor0000000000000000c3', self::binding(), $now));
        self::assertInstanceOf(IssuedCode::class, $codes->issue('01jfactor0000000000000000d1', self::binding(identity: '2'), $now));
    }

    /**
     * Sends leave oldest first whichever challenge they were for, so a later
     * resend leaves after an earlier send.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheIdentityCapWaitsForItsOldestSendsFirst(): void
    {
        $codes = $this->codes(['resend_cooldown_seconds' => 0], ['111111', '222222', '333333']);
        $now   = self::now();

        self::issued($codes->issue('01jfactor0000000000000000e1', self::binding(), $now));
        self::issued($codes->issue('01jfactor0000000000000000e2', self::binding(), $now->addSeconds(10)));

        $resent = self::issued($codes->issue('01jfactor0000000000000000e1', self::binding(), $now->addSeconds(20)));

        self::assertSame([$now->getTimestamp(), $now->addSeconds(20)->getTimestamp()], self::row($resent)->sent_times);

        $capped = $this->codes(['identity_send_limit' => 2], ['444444']);

        self::assertSame(3580, $capped->issue('01jfactor0000000000000000e3', self::binding(), $now->addSeconds(30)));
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEveryResendCountsTowardTheCaps(): void
    {
        $codes = $this->codes(['factor_send_limit' => 3, 'resend_cooldown_seconds' => 0], [self::CODE, self::NEXT_CODE, '111111', '222222']);
        $now   = self::now();

        self::issued($codes->issue(self::FACTOR, self::binding(), $now));
        self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $last = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertSame(array_fill(0, 3, $now->getTimestamp()), self::row($last)->sent_times);
        self::assertSame(3600, $codes->issue(self::FACTOR, self::binding(), $now));
    }

    /**
     * A refusal waits only until enough sends have left for one more.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachSendLeavesTheWindowOnItsOwn(): void
    {
        $codes = $this->codes(['factor_send_limit' => 2, 'send_window_minutes' => 5], ['111111', '222222', '333333']);
        $now   = self::now();

        self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $resent = self::issued($codes->issue(self::FACTOR, self::binding(), $now->addMinutes(4)));

        self::assertSame([$now->getTimestamp(), $now->addMinutes(4)->getTimestamp()], self::row($resent)->sent_times);
        self::assertSame(59, $codes->issue(self::FACTOR, self::binding(session: 'session-b'), $now->addSeconds(241)));
        self::assertInstanceOf(IssuedCode::class, $codes->issue(self::FACTOR, self::binding(session: 'session-b'), $now->addMinutes(5)));
        self::assertSame(180, $codes->issue(self::FACTOR, self::binding(session: 'session-c'), $now->addMinutes(6)));
    }

    /**
     * Without a generator every digit is drawn: across enough codes each of 0
     * to 9 turns up.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testACodeIsDigitsOfTheConfiguredLength(): void
    {
        $config = $this->container()->make(Repository::class);
        $config->set('mfa.codes.length', 8);

        $codes  = new DeliveredCodes($config);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        self::assertMatchesRegularExpression('/^\d{8}$/D', $issued->code);
        self::assertSame(CodeCheck::ACCEPTED, $codes->check(self::FACTOR, self::binding(), $issued->code, $now, $issued->challengeId));

        $digits = '';

        // 400 digits miss one of the ten with a chance of about 1 in 10^17
        for ($identity = 2; $identity <= 51; $identity++) {
            $code = self::issued($codes->issue(self::FACTOR . $identity, self::binding(identity: (string) $identity), $now))->code;

            self::assertMatchesRegularExpression('/^\d{8}$/D', $code);

            $digits .= $code;
        }

        $seen = array_unique(str_split($digits));

        sort($seen);

        self::assertSame(str_split('0123456789'), $seen);
    }

    /**
     * When a concurrent check used up the last attempt first, the challenge is
     * exhausted.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckOvertakenByAnotherAnswersFromAFreshRead(): void
    {
        $codes  = $this->codes(['max_attempts' => 1], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $this->onFirstRead(static fn () => Code::query()->whereKey($issued->challengeId)->update(['attempts' => 1]));

        self::assertSame(CodeCheck::EXHAUSTED, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
    }

    /**
     * The replacement code is untouched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckOvertakenByAResendIsInvalid(): void
    {
        $codes  = $this->codes([], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $this->onFirstRead(static fn () => Code::query()->whereKey($issued->challengeId)->update(['sends' => 2]));

        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(0, self::row($issued)->attempts);
        self::assertNull(self::row($issued)->consumed_at);
    }

    /**
     * Missing when a concurrent check used the code first, and counts no
     * attempt.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckOvertakenByAUseIsSpent(): void
    {
        $codes  = $this->codes([], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $this->onFirstRead(static fn () => Code::query()->whereKey($issued->challengeId)->update(['consumed_at' => $now]));

        self::assertSame(CodeCheck::SPENT, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(0, self::row($issued)->attempts);
    }

    /**
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckOvertakenByARemovalIsInvalid(): void
    {
        $codes  = $this->codes([], [self::CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));

        $this->onFirstRead(static fn () => Code::query()->whereKey($issued->challengeId)->delete());

        self::assertSame(CodeCheck::INVALID, $codes->check(self::FACTOR, self::binding(), self::CODE, $now, $issued->challengeId));
        self::assertSame(0, Code::query()->count());
    }

    /**
     * It sends nothing and asks for one second, leaving the other's code in
     * place.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendOvertakenByAnotherWaitsASecond(): void
    {
        $codes  = $this->codes(['resend_cooldown_seconds' => 60], [self::CODE, self::NEXT_CODE]);
        $now    = self::now();
        $issued = self::issued($codes->issue(self::FACTOR, self::binding(), $now));
        $hash   = self::row($issued)->code_hash;

        $this->onFirstRead(static fn () => Code::query()->whereKey($issued->challengeId)->update(['sends' => 2]));

        self::assertSame(1, $codes->issue(self::FACTOR, self::binding(), $now->addSeconds(60)));
        self::assertSame(2, self::row($issued)->sends);
        self::assertSame($hash, self::row($issued)->code_hash);
    }

    /**
     * The engine with the block's settings changed, drawing the given codes in
     * order.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $draws
     * @return \SineMacula\Laravel\Mfa\Codes\DeliveredCodes
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function codes(array $settings, array $draws): DeliveredCodes
    {
        $config = $this->container()->make(Repository::class);

        foreach ($settings as $key => $value) {
            $config->set('mfa.codes.' . $key, $value);
        }

        $this->draws = $draws;

        return new DeliveredCodes($config, fn (int $length): string => array_shift($this->draws) ?? str_repeat('9', $length));
    }

    /**
     * Run the change once on the next challenge read, as a concurrent request
     * would between a check's read and its writes.
     *
     * @param  \Closure(): mixed  $change
     * @return void
     */
    private function onFirstRead(\Closure $change): void
    {
        $done = false;

        Code::retrieved(static function () use (&$done, $change): void {

            if ($done) {
                return;
            }

            $done = true;

            $change();
        });
    }

    /**
     * @return \Carbon\CarbonImmutable
     */
    private static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01 12:00:00');
    }

    /**
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  string  $identity
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(string $session = 'session-a', Purpose $purpose = Purpose::SIGN_IN, string $application = 'web', string $identity = '1'): ProofBinding
    {
        return new ProofBinding(TestUser::class, $identity, $application, $session, $purpose);
    }

    /**
     * Assert the engine issued a code, and return it.
     *
     * @param  int|\SineMacula\Laravel\Mfa\Codes\IssuedCode  $issued
     * @return \SineMacula\Laravel\Mfa\Codes\IssuedCode
     */
    private static function issued(int|IssuedCode $issued): IssuedCode
    {
        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued;
    }

    /**
     * The stored challenge of an issued code, as it is now.
     *
     * @param  \SineMacula\Laravel\Mfa\Codes\IssuedCode  $issued
     * @return \SineMacula\Laravel\Mfa\Models\Code
     */
    private static function row(IssuedCode $issued): Code
    {
        $row = Code::query()->find($issued->challengeId);

        self::assertInstanceOf(Code::class, $row);

        return $row;
    }
}
