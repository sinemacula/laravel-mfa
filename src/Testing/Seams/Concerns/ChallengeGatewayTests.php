<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\ChallengeGatewayContract;

/**
 * The `ChallengeGateway` contract kit; each check delegates to
 * `ChallengeGatewayContract`.
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
     * @return void
     */
    public function testChallengeGatewayRefusesAWrongCode(): void
    {
        ChallengeGatewayContract::assertAWrongCodeIsRefused(
            $this->challengeGateway(),
            $this->challengeCaller(),
            $this->challengedFactor(),
            $this->challengeBinding(),
            $this->deliveredCode(...),
        );
    }

    /**
     * @return void
     */
    public function testChallengeGatewayAnswersOnlyTheCodesOwnBinding(): void
    {
        ChallengeGatewayContract::assertACodeAnswersOnlyItsOwnBinding(
            $this->challengeGateway(),
            $this->challengeCaller(),
            $this->challengedFactor(),
            $this->challengeBinding(),
            $this->deliveredCode(...),
        );
    }

    /**
     * @return void
     */
    public function testChallengeGatewayConsumesACodeOnce(): void
    {
        ChallengeGatewayContract::assertACodeIsConsumedOnce(
            $this->challengeGateway(),
            $this->challengeCaller(),
            $this->challengedFactor(),
            $this->challengeBinding(),
            $this->deliveredCode(...),
        );
    }

    /**
     * @return void
     */
    public function testChallengeGatewayDoesNotFindAnUnknownChallenge(): void
    {
        ChallengeGatewayContract::assertAnUnknownChallengeIsNotFound($this->challengeGateway(), $this->challengeCaller(), $this->challengedFactor(), $this->challengeBinding());
    }

    /**
     * The caller the binding is for, as the gateway is handed it.
     *
     * @return \SineMacula\Laravel\Mfa\Context\CallerContext
     */
    abstract protected function challengeCaller(): CallerContext;

    /**
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
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    abstract protected function challengeBinding(): ProofBinding;

    /**
     * The code last delivered for the challenge, as read from a fake sender.
     *
     * @param  string  $challengeId
     * @return string
     */
    abstract protected function deliveredCode(string $challengeId): string;
}
