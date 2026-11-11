<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * Answers the same proof, or none, whoever asks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FixedReauthenticator implements Reauthenticator
{
    /**
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     */
    public function __construct(

        /** `null` for none. */
        private ?Proof $proof,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    #[\Override]
    public function reauthenticate(MultiFactorAuthenticatable $identity, string $application): ?Proof
    {
        return $this->proof;
    }
}
