<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeGatewayContract;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeGatewayTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Seams\AcceptingChallengeGateway;
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

        ChallengeGatewayContract::assertAWrongCodeIsRefused(new AcceptingChallengeGateway, $this->factor, $this->emailBinding($this->user), static fn (string $challenge): string => '123456');
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function challengeGateway(): ChallengeGateway
    {
        return $this->container()->make(ChallengeGateway::class);
    }

    /**
     * The person's email factor.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    protected function challengedFactor(): Factor
    {
        return $this->factor;
    }

    /**
     * The person's sign-in binding.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
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
    protected function deliveredCode(string $challengeId): string
    {
        return self::lastEmailedCode($this->mailbox);
    }
}
