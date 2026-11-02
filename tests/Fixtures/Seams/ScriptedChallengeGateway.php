<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

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
     * @param  \Closure(string): bool  $accepts
     */
    public function __construct(

        /** Whether a code is accepted. */
        private \Closure $accepts,
    ) {}

    /**
     * A challenge id, with nothing sent.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return string
     */
    #[\Override]
    public function send(Factor $factor, ProofBinding $binding): string
    {
        return 'scripted-challenge';
    }

    /**
     * Whether the script accepts the code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  string  $challengeId
     * @param  string  $code
     * @return bool
     */
    #[\Override]
    public function verify(Factor $factor, ProofBinding $binding, string $challengeId, #[\SensitiveParameter] string $code): bool
    {
        return ($this->accepts)($code);
    }
}
