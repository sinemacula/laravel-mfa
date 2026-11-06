<?php

declare(strict_types = 1);

namespace Tests\Unit\Verification;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Context\Caller;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Verification\ProofAcceptance;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `ProofAcceptance`: whether a new proof refreshes multifactor is
 * judged on the session's first factor with it alone, by when the evidence was
 * made, so neither another proof the session holds nor the first factor alone
 * makes a weaker proof look fresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(VerificationResult::class)]
final class ProofAcceptanceTest extends TestCase
{
    /** @var string The pending session the proofs are made in. */
    private const string SESSION = 'pending-1';

    /** @var \Tests\Fixtures\Identities\TestUser The identity signing in. */
    private TestUser $user;

    /** @var \Tests\Fixtures\Requirements\SignInProofs The proofs of the pending session. */
    private SignInProofs $proofs;

    /**
     * Freeze the clock and arrange the identity.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-11-01 12:00:00');

        $this->user   = TestUser::query()->create(['email' => 'ada@example.test', 'mfa_enabled' => true]);
        $this->proofs = SignInProofs::of($this->user)->inSession(self::SESSION);
    }

    /**
     * A proof completing the combination with the first factor refreshes
     * multifactor.
     *
     * @return void
     */
    public function testAProofCompletingTheCombinationRefreshesMultifactor(): void
    {
        self::assertTrue($this->accept($this->proofs->password(1000), $this->proofs->totp())->refreshesMultifactor);
    }

    /**
     * A weaker proof after a first factor multifactor on its own refreshes
     * nothing, though the session is multifactor.
     *
     * @return void
     */
    public function testAWeakerProofAfterAMultifactorFirstFactorRefreshesNothing(): void
    {
        $result = $this->accept($this->proofs->passkey(true, 1000), $this->proofs->email());

        self::assertTrue($result->evaluation?->multifactor);
        self::assertFalse($result->refreshesMultifactor);
    }

    /**
     * A proof multifactor on its own refreshes multifactor, after a first
     * factor that is too.
     *
     * @return void
     */
    public function testAMultifactorProofRefreshesMultifactorAfterAMultifactorFirstFactor(): void
    {
        self::assertTrue($this->accept($this->proofs->passkey(true, 1000), $this->proofs->passkeyFactor(true))->refreshesMultifactor);
    }

    /**
     * Another proof the session holds does not make a weaker one refresh
     * multifactor, though the session is multifactor with it.
     *
     * @return void
     */
    public function testAnotherProofOfTheSessionMakesNoneFresh(): void
    {
        $result = $this->accept($this->proofs->password(1000), $this->proofs->email(), $this->proofs->totp(500));

        self::assertTrue($result->evaluation?->multifactor);
        self::assertFalse($result->refreshesMultifactor);
    }

    /**
     * A first factor and a proof made at the same instant share their
     * evidence's time, so the proof refreshes it; a different instant within
     * the same second does not.
     *
     * @return void
     */
    public function testOnlyTheSameInstantCountsAsTheProofsOwn(): void
    {
        self::assertTrue($this->accept($this->proofs->passkey(true), $this->proofs->email())->refreshesMultifactor);

        Carbon::setTestNow('2026-11-01 12:00:00.200000');

        $firstFactor = $this->proofs->passkey(true);

        Carbon::setTestNow('2026-11-01 12:00:00.700000');

        self::assertFalse($this->accept($firstFactor, $this->proofs->email())->refreshesMultifactor);
    }

    /**
     * A requirement check that does not say when its multifactor evidence was
     * made refreshes nothing.
     *
     * @return void
     */
    public function testACheckThatDoesNotSayWhenRefreshesNothing(): void
    {
        $this->container()->instance(RequirementCheck::class, new class implements RequirementCheck {
            /**
             * Answer multifactor, without saying when.
             *
             * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
             * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
             * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
             */
            #[\Override]
            public function check(Requirement $requirement, Proof ...$proofs): Evaluation
            {
                return new Evaluation(true, true, AssuranceLevel::AAL2, false, false, ['mfa'], [], []);
            }
        });

        self::assertFalse($this->accept($this->proofs->password(1000), $this->proofs->totp())->refreshesMultifactor);
    }

    /**
     * Accept the proof in a pending session begun with the first factor and
     * holding the other proofs.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$held
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     */
    private function accept(Proof $firstFactor, Proof $proof, Proof ...$held): VerificationResult
    {
        $pending = new PendingContext(
            identity   : $this->user,
            application: SignInProofs::APPLICATION,
            sessionId  : self::SESSION,
            firstFactor: $firstFactor,
            requirement: Requirement::none()->withAdditionalVerification(),
            actions    : [PendingAction::VERIFY],
            expiresAt  : CarbonImmutable::now()->addMinutes(10),
            proofs     : array_values($held),
        );

        return $this->container()->make(ProofAcceptance::class)->evaluate(new Caller($this->user, $pending, $pending->application), $proof, [], 'test');
    }
}
