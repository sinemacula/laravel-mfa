<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeGatewayContract;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeGatewayTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\AcceptingChallengeGateway;
use Tests\Fixtures\Seams\FaultyChallengeGatewayKit;
use Tests\Fixtures\Seams\MemoryChallengeGateway;
use Tests\Fixtures\Seams\ScriptedChallengeGateway;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayContract::class)]
#[CoversClass(PackageChallengeGateway::class)]
#[CoversTrait(ChallengeGatewayTests::class)]
final class ChallengeGatewayContractTest extends TestCase
{
    use ArrangesEmailChallenges, ChallengeGatewayTests;

    /** @var \Tests\Fixtures\Identities\TestUser The person challenged. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's email factor. */
    private FactorModel $factor;

    /** @var \SineMacula\Laravel\Mfa\Testing\FakeEmailSender The codes sent. */
    private FakeEmailSender $mailbox;

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        // So the kit sees the challenge run out, not the factor lock.
        config()->set('mfa.attempts.factor_limit', 10);

        [$this->user, $this->factor, $this->mailbox] = $this->arrangeEmailChallenges();
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatAcceptsAnyCode(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertAWrongCodeIsRefused(
            new AcceptingChallengeGateway,
            Callers::current(),
            $this->factor,
            $this->emailBinding($this->user),
            static fn (string $challenge): string => '123456',
        );
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatIgnoresThePurpose(): void
    {
        $this->expectException(AssertionFailedError::class);

        $binding = $this->emailBinding($this->user);

        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding(new AcceptingChallengeGateway, Callers::current(), $this->factor, $binding, self::sent(...));
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatRefusesEveryCode(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (): ChallengeOutcome => self::answer(false));

        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatConsumesNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertACodeIsConsumedOnce(new AcceptingChallengeGateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sentCodes(): iterable
    {
        yield 'a code of other digits' => ['123456'];
        yield 'a code of zeros' => ['000000'];
    }

    /**
     * The kit's wrong code has the sent code's length.
     *
     * @param  string  $sent
     * @return void
     */
    #[DataProvider('sentCodes')]
    public function testRejectsAGatewayThatChecksOnlyTheFormat(string $sent): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (string $code): ChallengeOutcome => self::answer(preg_match('/^\d{6}$/D', $code) === 1));

        $this->expectException(AssertionFailedError::class);

        $binding = $this->emailBinding($this->user);

        ChallengeGatewayContract::assertAWrongCodeIsRefused($gateway, Callers::current(), $this->factor, $binding, static fn (string $challenge): string => $sent);
    }

    /**
     * The kit's wrong code is never the one sent.
     *
     * @return void
     */
    public function testAcceptsAGatewayWhoseCodeIsAllZeros(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (string $code): ChallengeOutcome => self::answer($code === '000000'));

        $binding = $this->emailBinding($this->user);

        ChallengeGatewayContract::assertAWrongCodeIsRefused($gateway, Callers::current(), $this->factor, $binding, static fn (string $challenge): string => '000000');
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatCountsNothing(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (): ChallengeOutcome => ChallengeOutcome::refused(FailureReason::INVALID_CODE, 'No.'));

        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertAWrongCodeIsRefused($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatAnswersAnUnknownChallenge(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertAnUnknownChallengeIsNotFound(new AcceptingChallengeGateway, Callers::current(), $this->factor, $this->emailBinding($this->user));
    }

    /**
     * For a factor that may be challenged.
     *
     * @return void
     */
    public function testRejectsAGatewayThatSendsNothing(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (): ChallengeOutcome => self::answer(false), SendResult::refused(FailureReason::SENDING_CAPPED));

        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertACodeIsConsumedOnce($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * So each gateway it rejects is rejected for the part it leaves out.
     *
     * @return void
     */
    public function testAcceptsAGatewayThatChecksTheWholeBinding(): void
    {
        $gateway = new MemoryChallengeGateway;
        $caller  = Callers::current();
        $binding = $this->emailBinding($this->user);

        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding($gateway, $caller, $this->factor, $binding, self::sent(...));
        ChallengeGatewayContract::assertAnotherCallersBindingIsNotFound($gateway, $caller, $this->factor, $binding, self::sent(...));
        ChallengeGatewayContract::assertAChallengeTakesNoMoreThanItsAttempts($gateway, $caller, $this->factor, $binding, self::sent(...), 5);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function bindingPartsIgnored(): iterable
    {
        yield 'the purpose' => ['purpose', 'another purpose'];
        yield 'the session' => ['session_id', 'another session'];
        yield 'the application' => ['application', 'another application'];
    }

    /**
     * @param  string  $ignored
     * @param  string  $answered
     * @return void
     */
    #[DataProvider('bindingPartsIgnored')]
    public function testRejectsAGatewayThatIgnoresPartOfTheBinding(string $ignored, string $answered): void
    {
        $gateway = new MemoryChallengeGateway(array_values(array_diff(MemoryChallengeGateway::EVERY_PART, [$ignored])));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage(sprintf('must not answer %s than the one it was sent for', $answered));

        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function identityPartsIgnored(): iterable
    {
        yield 'the identity key' => ['identity_key'];
        yield 'the identity type' => ['identity_type'];
    }

    /**
     * @param  string  $ignored
     * @return void
     */
    #[DataProvider('identityPartsIgnored')]
    public function testRejectsAGatewayThatIgnoresTheIdentity(string $ignored): void
    {
        $gateway = new MemoryChallengeGateway(array_values(array_diff(MemoryChallengeGateway::EVERY_PART, [$ignored])));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not be found');

        ChallengeGatewayContract::assertAnotherCallersBindingIsNotFound($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * Its challenges still answer only their own binding.
     *
     * @return void
     */
    public function testRejectsAGatewayThatIgnoresTheCaller(): void
    {
        $gateway = new MemoryChallengeGateway(checksCaller: false);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not be found');

        ChallengeGatewayContract::assertAnotherCallersBindingIsNotFound($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatCountsAnotherCallersBinding(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (): ChallengeOutcome => ChallengeOutcome::failed(FailureReason::NOT_FOUND, 'No.'));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not be counted');

        ChallengeGatewayContract::assertAnotherCallersBindingIsNotFound($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatUsesUpTheCodeOnAnotherCallersBinding(): void
    {
        $asked   = 0;
        $gateway = new ScriptedChallengeGateway(static function () use (&$asked): ChallengeOutcome {
            return ++$asked <= 3 ? ChallengeOutcome::refused(FailureReason::NOT_FOUND, 'No.') : ChallengeOutcome::failed(FailureReason::REPLAYED, 'Used.');
        });

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not use up the code');

        ChallengeGatewayContract::assertAnotherCallersBindingIsNotFound($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * @return void
     */
    public function testTheKitRejectsAGatewayThatIgnoresTheCaller(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('must not be found');

        (new FaultyChallengeGatewayKit('kit'))->testChallengeGatewayDoesNotFindAnotherCallersBinding();
    }

    /**
     * @return void
     */
    public function testTheKitRejectsAGatewayWithNoAttemptLimit(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('once its challenge has taken its attempts');

        (new FaultyChallengeGatewayKit('kit'))->testChallengeGatewayRefusesTheCodeOnceItsAttemptsAreTaken();
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayWithNoAttemptLimit(): void
    {
        $gateway = new MemoryChallengeGateway(maxAttempts: null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('once its challenge has taken its attempts');

        ChallengeGatewayContract::assertAChallengeTakesNoMoreThanItsAttempts($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...), 5);
    }

    /**
     * @return void
     */
    public function testRejectsAGatewayThatTakesOneAttemptTooMany(): void
    {
        $gateway = new MemoryChallengeGateway(maxAttempts: 6);

        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertAChallengeTakesNoMoreThanItsAttempts($gateway, Callers::current(), $this->factor, $this->emailBinding($this->user), self::sent(...), 5);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function challengeGateway(): ChallengeGateway
    {
        return $this->container()->make(ChallengeGateway::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    #[\Override]
    protected function challengedFactor(): Factor
    {
        return $this->factor;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function challengeBinding(): ProofBinding
    {
        return $this->emailBinding($this->user);
    }

    /**
     * @param  string  $challengeId
     * @return string
     */
    #[\Override]
    protected function deliveredCode(string $challengeId): string
    {
        return self::lastEmailedCode($this->mailbox);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function challengeCaller(): CallerContext
    {
        return Callers::current();
    }

    /**
     * @param  bool  $passes
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     */
    private static function answer(bool $passes): ChallengeOutcome
    {
        return $passes ? ChallengeOutcome::passed() : ChallengeOutcome::failed(FailureReason::INVALID_CODE, 'No.');
    }

    /**
     * @param  string  $challenge
     * @return string
     */
    private static function sent(string $challenge): string
    {
        return MemoryChallengeGateway::CODE;
    }
}
