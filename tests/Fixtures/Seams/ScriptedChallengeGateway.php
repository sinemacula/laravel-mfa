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
 * A challenge gateway that sends nothing and answers each code as its script
 * says, so the challenge gateway kit can be shown a gateway that refuses every
 * code, one that checks only a code's format, and one with a fixed code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ScriptedChallengeGateway implements ChallengeGateway
{
    /**
     * Constructor.
     *
     * @param  \Closure(string, string): \SineMacula\Laravel\Mfa\Attempts\ChallengeOutcome  $answers
     * @param  ?\SineMacula\Laravel\Mfa\Codes\SendResult  $sent
     */
    public function __construct(

        /** How the code and the challenge named are answered. */
        private \Closure $answers,

        /** What a send answers, or a challenge sent. */
        private ?SendResult $sent = null,
    ) {}

    /**
     * The answer scripted, or a challenge id with nothing sent.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Codes\SendResult
     */
    #[\Override]
    public function send(Factor $factor, ProofBinding $binding): SendResult
    {
        return $this->sent ?? SendResult::sent('scripted-challenge', CarbonImmutable::now()->addMinutes(5));
    }

    /**
     * The outcome the script gives the code.
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
        return ($this->answers)($code, $challengeId);
    }
}
