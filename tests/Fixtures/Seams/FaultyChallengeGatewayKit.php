<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\Factor as FactorModel;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ChallengeGatewayTests;
use Tests\Fixtures\Context\Callers;

/**
 * The challenge gateway kit over a gateway that answers any caller and takes
 * any number of wrong codes, with no second caller unless one is set, for
 * running its checks as PHPUnit does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class FaultyChallengeGatewayKit extends TestCase
{
    use ChallengeGatewayTests;

    /** @var ?array{0: \SineMacula\Laravel\Mfa\Context\CallerContext, 1: \SineMacula\Laravel\Mfa\Proofs\ProofBinding} The identity on another session, with the binding it holds there. */
    public ?array $secondCaller = null;

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
     * @return \SineMacula\Laravel\Mfa\Contracts\ChallengeGateway
     */
    #[\Override]
    protected function challengeGateway(): ChallengeGateway
    {
        return new MemoryChallengeGateway(maxAttempts: null, checksCaller: false);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\Factor
     */
    #[\Override]
    protected function challengedFactor(): Factor
    {
        return new FactorModel;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function challengeBinding(): ProofBinding
    {
        return new ProofBinding('user', '1', 'web', 'sign-in-1', Purpose::STEP_UP);
    }

    /**
     * @param  string  $challengeId
     * @return string
     */
    #[\Override]
    protected function deliveredCode(string $challengeId): string
    {
        return MemoryChallengeGateway::CODE;
    }

    /**
     * @return ?array{0: \SineMacula\Laravel\Mfa\Context\CallerContext, 1: \SineMacula\Laravel\Mfa\Proofs\ProofBinding}
     */
    protected function secondChallengeCaller(): ?array
    {
        return $this->secondCaller;
    }
}
