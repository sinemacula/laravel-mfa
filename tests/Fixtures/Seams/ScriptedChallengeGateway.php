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
 * Sends nothing and answers each code as its script says, for showing the
 * challenge gateway kit faulty gateways.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScriptedChallengeGateway implements ChallengeGateway
{
    /**
     * @param  \Closure(string, string): \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome  $answers
     * @param  ?\SineMacula\Laravel\Mfa\Codes\SendResult  $sent
     */
    public function __construct(

        /** Answers the code and challenge id. */
        private \Closure $answers,

        /** What a send answers; a challenge sent when `null`. */
        private ?SendResult $sent = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\CallerContext  $caller
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     */
    #[\Override]
    public function send(CallerContext $caller, Factor $factor, ProofBinding $binding): SendResult
    {
        return $this->sent ?? SendResult::sent('scripted-challenge', CarbonImmutable::now()->addMinutes(5));
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
        return ($this->answers)($code, $challengeId);
    }
}
