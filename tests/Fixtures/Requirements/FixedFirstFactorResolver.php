<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A first factor resolver that reports the same proof, or none, whoever asks,
 * and counts how often it is asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedFirstFactorResolver implements FirstFactorResolver
{
    /** @var int How often the resolver has been asked. */
    public int $asked = 0;

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     */
    public function __construct(

        /** The proof reported, or `null` for none. */
        private readonly ?Proof $firstFactor,
    ) {}

    /**
     * Report the fixed proof.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    #[\Override]
    public function resolve(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        $this->asked++;

        return $this->firstFactor;
    }
}
