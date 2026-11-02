<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeGatewayContract;

/**
 * The `ChallengeGateway` contract kit: a wrong code fails and is counted, a
 * code answers only its own binding, a code is consumed once, and an unknown
 * challenge is not found.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ChallengeGatewayContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ChallengeGatewayTests
{
    /**
     * A code other than the one sent is refused.
     *
     * @return void
     */
    public function testChallengeGatewayRefusesAWrongCode(): void
    {
        ChallengeGatewayContract::assertAWrongCodeIsRefused($this->challengeGateway(), $this->challengedFactor(), $this->challengeBinding(), $this->deliveredCode(...));
    }

    /**
     * A code answers its own binding and no other purpose's.
     *
     * @return void
     */
    public function testChallengeGatewayAnswersOnlyTheCodesOwnBinding(): void
    {
        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding($this->challengeGateway(), $this->challengedFactor(), $this->challengeBinding(), $this->deliveredCode(...));
    }

    /**
     * A code answers once.
     *
     * @return void
     */
    public function testChallengeGatewayConsumesACodeOnce(): void
    {
        ChallengeGatewayContract::assertACodeIsConsumedOnce($this->challengeGateway(), $this->challengedFactor(), $this->challengeBinding(), $this->deliveredCode(...));
    }

    /**
     * A challenge that is not the binding's is not found.
     *
     * @return void
     */
    public function testChallengeGatewayDoesNotFindAnUnknownChallenge(): void
    {
        ChallengeGatewayContract::assertAnUnknownChallengeIsNotFound($this->challengeGateway(), $this->challengedFactor(), $this->challengeBinding());
    }

    /**
     * The gateway under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway
     */
    abstract protected function challengeGateway(): ChallengeGateway;

    /**
     * A confirmed delivered factor the gateway may send a code for.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    abstract protected function challengedFactor(): Factor;

    /**
     * What the codes are bound to.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    abstract protected function challengeBinding(): ProofBinding;

    /**
     * The code last delivered for the challenge, as a test reads it from a fake
     * sender.
     *
     * @param  string  $challengeId
     * @return string
     */
    abstract protected function deliveredCode(string $challengeId): string;
}
