<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Context\CallerContext;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Admits whatever it is handed and counts the sends, so what it sends is only
 * what the package let through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingChallengeGateway implements ChallengeGateway
{
    /** @var int */
    public int $sends = 0;

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     */
    #[\Override]
    public function send(CallerContext $caller, Factor $factor, ProofBinding $binding): SendResult
    {
        $this->sends++;

        return SendResult::sent('counted-challenge-' . $this->sends, CarbonImmutable::now()->addMinutes(5));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     */
    #[\Override]
    public function verify(CallerContext $caller, Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        return ChallengeOutcome::passed();
    }
}
