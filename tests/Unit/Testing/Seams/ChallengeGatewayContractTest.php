<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeGatewayContract;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeGatewayTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\AcceptingChallengeGateway;
use Tests\Fixtures\Seams\ScriptedChallengeGateway;
use Tests\TestCase;

/**
 * The `ChallengeGateway` contract kit proves the package's own codes, and
 * rejects a gateway that accepts every code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeGatewayContract::class)]
#[CoversClass(PackageChallengeGateway::class)]
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
     * Sign a person in with an email factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        [$this->user, $this->factor, $this->mailbox] = $this->arrangeEmailChallenges();
    }

    /**
     * The kit rejects a gateway that accepts a wrong code.
     *
     * @return void
     */
    public function testRejectsAGatewayThatAcceptsAnyCode(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertAWrongCodeIsRefused(
            new AcceptingChallengeGateway,
            $this->factor,
            $this->emailBinding($this->user),
            static fn (string $challenge): string => '123456',
        );
    }

    /**
     * The kit rejects a gateway whose code answers another purpose.
     *
     * @return void
     */
    public function testRejectsAGatewayThatIgnoresThePurpose(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding(new AcceptingChallengeGateway, $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * The kit rejects a gateway whose code answers nothing.
     *
     * @return void
     */
    public function testRejectsAGatewayThatRefusesEveryCode(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (string $code): bool => false);

        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding($gateway, $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * The kit rejects a gateway whose code answers twice.
     *
     * @return void
     */
    public function testRejectsAGatewayThatConsumesNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertACodeIsConsumedOnce(new AcceptingChallengeGateway, $this->factor, $this->emailBinding($this->user), self::sent(...));
    }

    /**
     * Rows of a code sent.
     *
     * @return iterable<string, array{string}>
     */
    public static function sentCodes(): iterable
    {
        yield 'a code of other digits' => ['123456'];
        yield 'a code of zeros' => ['000000'];
    }

    /**
     * The kit tries a wrong code of the sent code's length, so it rejects a
     * gateway that checks only a code's format.
     *
     * @param  string  $sent
     * @return void
     */
    #[DataProvider('sentCodes')]
    public function testRejectsAGatewayThatChecksOnlyTheFormat(string $sent): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (string $code): bool => preg_match('/^\d{6}$/D', $code) === 1);

        $this->expectException(AssertionFailedError::class);

        ChallengeGatewayContract::assertAWrongCodeIsRefused($gateway, $this->factor, $this->emailBinding($this->user), static fn (string $challenge): string => $sent);
    }

    /**
     * A gateway whose code is all zeros passes: the kit's wrong code is never
     * the one sent.
     *
     * @return void
     */
    public function testAcceptsAGatewayWhoseCodeIsAllZeros(): void
    {
        $gateway = new ScriptedChallengeGateway(static fn (string $code): bool => $code === '000000');

        ChallengeGatewayContract::assertAWrongCodeIsRefused($gateway, $this->factor, $this->emailBinding($this->user), static fn (string $challenge): string => '000000');
    }

    /**
     * The bound default.
     *
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
     * The person's email factor.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    #[\Override]
    protected function challengedFactor(): Factor
    {
        return $this->factor;
    }

    /**
     * The person's sign-in binding.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function challengeBinding(): ProofBinding
    {
        return $this->emailBinding($this->user);
    }

    /**
     * The code last emailed.
     *
     * @param  string  $challengeId
     * @return string
     */
    #[\Override]
    protected function deliveredCode(string $challengeId): string
    {
        return self::lastEmailedCode($this->mailbox);
    }

    /**
     * The code a scripted or accepting gateway takes as sent.
     *
     * @param  string  $challenge
     * @return string
     */
    private static function sent(string $challenge): string
    {
        return '123456';
    }
}
