<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Reports the same proof, or none, whoever asks, and counts the calls.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedFirstFactorResolver implements FirstFactorResolver
{
    /** @var int */
    public int $asked = 0;

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     */
    public function __construct(

        /** `null` for none. */
        private readonly ?Proof $firstFactor,
    ) {}

    /**
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
