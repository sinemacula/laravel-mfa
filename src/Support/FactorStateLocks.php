<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The owners whose identity state row a running factor state callback holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorStateLocks
{
    /** @var list<string> Owner hashes, innermost callback last. */
    private array $held = [];

    /**
     * @template TReturn
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public function hold(ProofOwner $owner, \Closure $callback): mixed
    {
        $this->held[] = $owner->hash();

        try {
            return $callback();
        } finally {
            array_pop($this->held);
        }
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @return bool
     */
    public function holds(ProofOwner $owner): bool
    {
        return in_array($owner->hash(), $this->held, true);
    }
}
