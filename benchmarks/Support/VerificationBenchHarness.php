<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\MfaManager;
use SineMacula\Laravel\Mfa\RecoveryCodes\RecoveryCodeService;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Verification\Submission;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Identities\TestUser;

/**
 * One branch of a whole verification through the manager, measured once in a
 * process.
 *
 * Two people are seeded, each with their own sign-in, factors and address, so
 * every limiter key is separate. Building the harness runs the branch on the
 * first, which warms the path, as the CLI has no opcache and a first call would
 * time the autoloader, and proves it reaches its outcome. `run()` makes the
 * same call for the second, so it makes exactly the statements of a first
 * window that the query budget's ledger counts.
 *
 * A step or a code is used up by its verification and a miss counts, so a call
 * is never repeated: there is no pool of fixtures and the clock never moves,
 * and a second `run()` in a process throws, which is why the subject stays at
 * one revolution with no warm-up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class VerificationBenchHarness
{
    /** @var string A TOTP code accepted. */
    public const string TOTP_HIT = 'TOTP hit';

    /** @var string A wrong TOTP code. */
    public const string TOTP_MISS = 'TOTP miss';

    /** @var string A delivered code accepted. */
    public const string CODE_HIT = 'delivered code hit';

    /** @var string A wrong delivered code. */
    public const string CODE_MISS = 'delivered code miss';

    /** @var string A recovery code accepted. */
    public const string RECOVERY_CODE_HIT = 'recovery code hit';

    /** @var string A wrong recovery code. */
    public const string RECOVERY_CODE_MISS = 'recovery code miss';

    /** @var int How many steps away a wrong TOTP code is taken from. */
    private const int WRONG_STEPS = 5;

    /** @var string A code no recovery code can be. */
    private const string NO_RECOVERY_CODE = 'ZZZZ-ZZZZ-ZZZZ';

    /** @var array<string, true> @managed-static The branches already run in this process, outside anything set-up resets. */
    private static array $spent = [];

    /** @var \Illuminate\Contracts\Foundation\Application */
    private readonly Application $app;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The delivered codes. */
    private readonly FakeEmailSender $mailbox;

    /** @var \SineMacula\Laravel\Mfa\MfaManager */
    private readonly MfaManager $manager;

    /** @var \SineMacula\Laravel\Mfa\Verification\Submission What the timed call submits. */
    private readonly Submission $submission;

    /** @var ?\SineMacula\Laravel\Mfa\Verification\VerificationResult What the timed call answered. */
    private ?VerificationResult $result = null;

    /**
     * Build the application, prove the branch on the first person and arrange
     * it for the second.
     *
     * @param  string  $branch
     * @return void
     *
     * @throws \LogicException
     */
    public function __construct(

        /** The branch measured. */
        private readonly string $branch,
    ) {
        BenchApplication::freezeClock();

        $this->app     = BenchApplication::create();
        $this->mailbox = FakeEmailSender::fake($this->app);
        $this->manager = $this->app->make('mfa');

        $this->prove($this->manager->verify($this->arrange('warm-up@example.test', '198.51.100.1', 'bench-warm-up')));

        $this->submission = $this->arrange('timed@example.test', '198.51.100.2', 'bench-timed');
    }

    /**
     * Run the branch for the second person, once.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function run(): void
    {
        if (isset(self::$spent[$this->branch])) {
            throw new \LogicException(sprintf('The %s benchmark runs once in a process, as its fixture is used up; do not raise its revolutions or warm it up.', $this->branch));
        }

        self::$spent[$this->branch] = true;

        $this->result = $this->manager->verify($this->submission);
    }

    /**
     * Prove the timed call reached its outcome too, and release the clock.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function finish(): void
    {
        BenchOutcome::assert($this->branch, $this->result !== null);

        if ($this->result !== null) {
            $this->prove($this->result);
        }

        BenchApplication::releaseClock();
    }

    /**
     * Throw unless the answer is the one the branch is named for.
     *
     * @param  \SineMacula\Laravel\Mfa\Verification\VerificationResult  $result
     * @return void
     *
     * @throws \LogicException
     */
    private function prove(VerificationResult $result): void
    {
        $passes = in_array($this->branch, [self::TOTP_HIT, self::CODE_HIT, self::RECOVERY_CODE_HIT], true);

        BenchOutcome::assert($this->branch, $passes ? $result->isVerified() : $result->reason === FailureReason::INVALID_CODE);
    }

    /**
     * Seed a person for the branch and return what they submit.
     *
     * @param  string  $email
     * @param  string  $ip
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    private function arrange(string $email, string $ip, string $session): Submission
    {
        $user = BenchApplication::signedInPerson($this->app, $email, $ip, $session);

        return match ($this->branch) {
            self::TOTP_HIT          => $this->totpSubmission($user, 0),
            self::TOTP_MISS         => $this->totpSubmission($user, self::WRONG_STEPS),
            self::CODE_HIT          => $this->codeSubmission($user, true),
            self::CODE_MISS         => $this->codeSubmission($user, false),
            self::RECOVERY_CODE_HIT => Submission::recoveryCode($this->recoveryCode($user)),
            default                 => $this->wrongRecoveryCode($user),
        };
    }

    /**
     * A TOTP code of a new factor, from the number of steps away given.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  int  $steps
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    private function totpSubmission(TestUser $user, int $steps): Submission
    {
        $factor = BenchApplication::totpFactor($user);

        return Submission::factor($factor->id, AuthenticatorApp::code($factor, $steps));
    }

    /**
     * The code sent to a new email factor, or a wrong one.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  bool  $right
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     *
     * @throws \LogicException
     */
    private function codeSubmission(TestUser $user, bool $right): Submission
    {
        $factor    = BenchApplication::emailFactor($user);
        $challenge = $this->manager->sendCode($factor->id)->challengeId;
        $code      = $this->mailbox->lastCodeTo($user->email);

        if ($challenge === null || $code === null) {
            throw new \LogicException(sprintf('The %s benchmark could not send its code.', $this->branch));
        }

        $wrong = $code === '000000' ? '111111' : '000000';

        return Submission::challenge($factor->id, $challenge, $right ? $code : $wrong);
    }

    /**
     * A wrong code against the person's new set.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    private function wrongRecoveryCode(TestUser $user): Submission
    {
        $this->recoveryCode($user);

        return Submission::recoveryCode(self::NO_RECOVERY_CODE);
    }

    /**
     * Give the person a TOTP factor and a set of recovery codes, and return one
     * of the set.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return string
     *
     * @throws \LogicException
     */
    private function recoveryCode(TestUser $user): string
    {
        BenchApplication::totpFactor($user);

        $code = $this->app->make(RecoveryCodeService::class)->generate($user, null, BenchApplication::APPLICATION)[0] ?? null;

        if (!$code instanceof RevealedSecret) {
            throw new \LogicException(sprintf('The %s benchmark could not generate its recovery codes.', $this->branch));
        }

        return $code->reveal();
    }
}
