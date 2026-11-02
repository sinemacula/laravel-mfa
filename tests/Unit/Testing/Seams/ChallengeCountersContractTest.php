<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Attempts\ChallengeCounters;
use SineMacula\Laravel\Mfa\Codes\PackageChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\FakeEmailSender;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersContract;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeCountersTests;
use Tests\Fixtures\Codes\Concerns\ArrangesEmailChallenges;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The challenge counters wiring kit proves the package's own challenge
 * gateway, which counts every outcome inside its transaction, and rejects a
 * challenge path that counts nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeCountersContract::class)]
#[CoversClass(ChallengeCounters::class)]
#[CoversClass(PackageChallengeGateway::class)]
final class ChallengeCountersContractTest extends TestCase
{
    use ArrangesEmailChallenges, ChallengeCountersTests;

    /** @var \Tests\Fixtures\Identities\TestUser The person challenged. */
    private TestUser $user;

    /** @var \SineMacula\Laravel\Mfa\Models\Factor The person's email factor. */
    private Factor $factor;

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
     * The kit rejects a challenge path that counts nothing.
     *
     * @return void
     */
    public function testRejectsAPathThatCountsNothing(): void
    {
        $this->expectException(AssertionFailedError::class);

        ChallengeCountersContract::assertAFailedChallengeIsCounted($this->factor, static function (): void {
            // A path that checks its own code and never reports the outcome.
        });
    }

    /**
     * The person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function countedIdentity(): MultiFactorAuthenticatable
    {
        return $this->user;
    }

    /**
     * The person's email factor.
     *
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Mfa\Contracts\EloquentFactor
     */
    protected function countedFactor(): EloquentFactor&Model
    {
        return $this->factor;
    }

    /**
     * The person's sign-in binding.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    protected function countedBinding(): ProofBinding
    {
        return $this->emailBinding($this->user);
    }

    /**
     * Send a code through the default gateway and submit a wrong one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    protected function failChallenge(): void
    {
        $gateway   = $this->container()->make(ChallengeGateway::class);
        $binding   = $this->emailBinding($this->user);
        $challenge = $gateway->send($this->factor, $binding);
        $code      = self::lastEmailedCode($this->mailbox);

        $gateway->verify($this->factor, $binding, $challenge, $code === '000000' ? '111111' : '000000');
    }
}
