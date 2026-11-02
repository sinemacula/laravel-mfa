<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\ChallengeGateway;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * A faulty challenge gateway: it sends nothing and accepts every code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AcceptingChallengeGateway implements ChallengeGateway
{
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
        return 'accepting-challenge';
    }

    /**
     * Accept the code, whatever it is.
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
        return true;
    }
}
