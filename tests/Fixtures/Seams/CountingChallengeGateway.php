<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome;
use SineMacula\Laravel\Mfa\Codes\SendResult;
use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * A challenge gateway that admits whatever it is handed and counts the sends,
 * as an application's own gateway might, checking no admission itself: what it
 * sends is only what the package let through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingChallengeGateway implements ChallengeGateway
{
    /** @var int How many sends the gateway was asked for. */
    public int $sends = 0;

    /**
     * Send, counting it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     */
    #[\Override]
    public function send(Factor $factor, ProofBinding $binding): SendResult
    {
        $this->sends++;

        return SendResult::sent('counted-challenge-' . $this->sends, CarbonImmutable::now()->addMinutes(5));
    }

    /**
     * Pass every answer.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome
     */
    #[\Override]
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): ChallengeOutcome
    {
        return ChallengeOutcome::passed();
    }
}
