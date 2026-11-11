<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingCompletionTests;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\StepUpTests;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingCompletionContract;
use SineMacula\Laravel\Mfa\Testing\Seams\StepUpContract;
use SineMacula\Laravel\Mfa\Verification\VerificationResult;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\CheckingCompletion;
use Tests\Fixtures\Seams\RefusingCompletion;
use Tests\TestCase;

/**
 * The package's own default, which records in the proof store, passes both
 * kits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingCompletionContract::class)]
#[CoversClass(StepUpContract::class)]
final class CompletionContractTest extends TestCase
{
    use PendingCompletionTests, StepUpTests;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsAPendingCompletionThatAcceptsAnything(): void
    {
        $this->expectException(AssertionFailedError::class);

        PendingCompletionContract::assertRefusesAResultOfAnotherBinding(new CheckingCompletion('sign-in-1', false), $this->pendingCaller(), $this->resultOfAnotherBinding());
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsAPendingCompletionThatTakesNoPendingSessionOrRefusesItsOwn(): void
    {
        $caller   = $this->pendingCaller();
        $matching = $this->resultOfThePendingSession();
        $taker    = new CheckingCompletion('sign-in-1', false);
        $refuser  = new RefusingCompletion(new OperationRefusedException(FailureReason::NOT_ACCEPTED, 'Refused.'));
        $taking   = self::rejection(static fn () => PendingCompletionContract::assertRefusesACallerWithNoPendingSession($taker, $caller, $matching));
        $refusing = self::rejection(static fn () => PendingCompletionContract::assertAcceptsAResultOfThePendingSession($refuser, $caller, $matching));

        self::assertNotNull($taking);
        self::assertStringContainsString('no pending session must be refused', $taking->getMessage());
        self::assertNotNull($refusing);
        self::assertStringContainsString('must be accepted', $refusing->getMessage());
    }

    /**
     * @return void
     */
    public function testRejectsAStepUpThatAcceptsAFailedResult(): void
    {
        $this->expectException(AssertionFailedError::class);

        StepUpContract::assertRefusesAFailedResult(new CheckingCompletion('sign-in-1', false), Callers::current());
    }

    /**
     * Anything but an `OperationRefusedException`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsASeamThatThrowsAnythingElse(): void
    {
        $this->expectException(AssertionFailedError::class);

        StepUpContract::assertRefusesAResultOfAnotherBinding(new RefusingCompletion(new \RuntimeException('Not a reason.')), Callers::current(), $this->resultOfAnotherBinding());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingCompletion
     */
    #[\Override]
    protected function pendingCompletion(): PendingCompletion
    {
        return new CheckingCompletion('sign-in-1');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    #[\Override]
    protected function pendingContext(): PendingContext
    {
        $identity = new NonEloquentIdentity;

        return new PendingContext(
            $identity,
            'web',
            'pending-1',
            SignInProofs::of($identity)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addHour(),
        );
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function resultOfThePendingSession(): VerificationResult
    {
        $proof = SignInProofs::of(new NonEloquentIdentity)->inSession('pending-1')->totp();

        return VerificationResult::verified($proof, $this->container()->make(RequirementCheck::class)->check(Requirement::none(), $proof), ['otp'], 'totp');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function resultOfAnotherBinding(): VerificationResult
    {
        $proof = SignInProofs::of(new NonEloquentIdentity)->inSession('another-session')->totp();

        return VerificationResult::verified($proof, $this->container()->make(RequirementCheck::class)->check(Requirement::none(), $proof), ['otp'], 'totp');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\StepUp
     */
    #[\Override]
    protected function stepUp(): StepUp
    {
        return new CheckingCompletion('sign-in-1');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Verification\VerificationResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function stepUpResultOfAnotherBinding(): VerificationResult
    {
        return $this->resultOfAnotherBinding();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function stepUpCaller(): CallerContext
    {
        return Callers::current();
    }

    /**
     * `null` when the check accepts what it is given.
     *
     * @param  \Closure(): void  $check
     * @return ?\PHPUnit\Framework\AssertionFailedError
     */
    private static function rejection(\Closure $check): ?AssertionFailedError
    {
        try {
            $check();
        } catch (AssertionFailedError $failure) {
            return $failure;
        }

        return null;
    }
}
