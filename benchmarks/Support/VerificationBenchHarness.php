<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\CallerContext;
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
 * Runs a branch on a first person to warm the path, as the CLI has no opcache,
 * then times it once for a second; a used-up step or code allows no repeat.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class VerificationBenchHarness
{
    /** @var string */
    public const string TOTP_HIT = 'TOTP hit';

    /** @var string */
    public const string TOTP_MISS = 'TOTP miss';

    /** @var string */
    public const string CODE_HIT = 'delivered code hit';

    /** @var string */
    public const string CODE_MISS = 'delivered code miss';

    /** @var string */
    public const string RECOVERY_CODE_HIT = 'recovery code hit';

    /** @var string */
    public const string RECOVERY_CODE_MISS = 'recovery code miss';

    /** @var int Steps away a wrong TOTP code is taken from. */
    private const int WRONG_STEPS = 5;

    /** @var string Matches none of the set. */
    private const string NO_RECOVERY_CODE = 'ZZZZ-ZZZZ-ZZZZ';

    /** @var array<string, true> @managed-static Branches run in this process; set-up never resets it. */
    private static array $spent = [];

    /** @var \Illuminate\Contracts\Foundation\Application */
    private readonly Application $app;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender */
    private readonly FakeEmailSender $mailbox;

    /** @var \SineMacula\Laravel\Mfa\MfaManager */
    private readonly MfaManager $manager;

    /** @var \SineMacula\Laravel\Mfa\Verification\Submission */
    private readonly Submission $submission;

    /** @var \SineMacula\Laravel\Mfa\Context\CallerContext */
    private readonly CallerContext $caller;

    /** @var ?\SineMacula\Laravel\Mfa\Verification\VerificationResult */
    private ?VerificationResult $result = null;

    /**
     * @param  string  $branch
     * @return void
     *
     * @throws \LogicException
     */
    public function __construct(

        /** Branch measured. */
        private readonly string $branch,
    ) {
        BenchApplication::freezeClock();

        $this->app     = BenchApplication::create();
        $this->mailbox = FakeEmailSender::fake($this->app);
        $this->manager = $this->app->make('mfa');

        $warmUp = $this->arrange('warm-up@example.test', '198.51.100.1', 'bench-warm-up');

        $this->prove($this->manager->verify($this->currentCaller(), $warmUp));

        $this->submission = $this->arrange('timed@example.test', '198.51.100.2', 'bench-timed');
        $this->caller     = $this->currentCaller();
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

        $this->result = $this->manager->verify($this->caller, $this->submission);
    }

    /**
     * Prove the timed call's outcome and release the clock.
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
            self::CODE_HIT          => $this->codeSubmission($user, $email, true),
            self::CODE_MISS         => $this->codeSubmission($user, $email, false),
            self::RECOVERY_CODE_HIT => Submission::recoveryCode($this->recoveryCode($user)),
            default                 => $this->wrongRecoveryCode($user),
        };
    }

    /**
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
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @param  string  $email
     * @param  bool  $right
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     *
     * @throws \LogicException
     */
    private function codeSubmission(TestUser $user, string $email, bool $right): Submission
    {
        $factor    = BenchApplication::emailFactor($user);
        $challenge = $this->manager->sendCode($this->currentCaller(), $factor->id)->challengeId;
        $code      = $this->mailbox->lastCodeTo($email);

        if ($challenge === null || $code === null) {
            throw new \LogicException(sprintf('The %s benchmark could not send its code.', $this->branch));
        }

        $wrong = $code === '000000' ? '111111' : '000000';

        return Submission::challenge($factor->id, $challenge, $right ? $code : $wrong);
    }

    /**
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return \SineMacula\Laravel\Mfa\Verification\Submission
     */
    private function wrongRecoveryCode(TestUser $user): Submission
    {
        $this->recoveryCode($user);

        return Submission::recoveryCode(self::NO_RECOVERY_CODE);
    }

    /**
     * Give the person a TOTP factor and recovery codes, and return one.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return string
     *
     * @throws \LogicException
     */
    private function recoveryCode(TestUser $user): string
    {
        BenchApplication::totpFactor($user);

        $code = $this->app->make(RecoveryCodeService::class)->generate($user, BenchApplication::APPLICATION)[0] ?? null;

        if (!$code instanceof RevealedSecret) {
            throw new \LogicException(sprintf('The %s benchmark could not generate its recovery codes.', $this->branch));
        }

        return $code->reveal();
    }

    /**
     * As an application's controller builds it.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    private function currentCaller(): CallerContext
    {
        return CallerContext::fromRequest($this->app->make(Request::class), null, $this->app);
    }
}
