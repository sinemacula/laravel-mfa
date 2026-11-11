<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use Tests\Fixtures\Seams\LayerWrittenProofStore;

/**
 * Records through the layer that writes the store's sign-ins and proofs,
 * enrolling a factor for a proof that names one since the store counts a proof
 * only while its factor is held.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LayerRecorder implements VerifiedSignInRecorder
{
    /**
     * @param  \Tests\Fixtures\Seams\LayerWrittenProofStore  $layer
     */
    public function __construct(

        /** Its layer writes the sign-ins and proofs. */
        private LayerWrittenProofStore $layer,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string // NOSONAR: the layer keeps no start time
    {
        $session = $this->layer->signIn();

        $this->layer->begin($identity, $application, $session);

        return $session;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     */
    #[\Override]
    public function record(MultiFactorAuthenticatable $identity, Proof $proof): void
    {
        $this->layer->write(new Proof(
            kind: $proof->kind,
            method: $proof->method,
            channel: $proof->channel,
            reference: $proof->reference === null ? null : $this->layer->enrol(),
            properties: $proof->properties,
            provedAt: $proof->provedAt,
            binding: $proof->binding,
            generation: $proof->generation,
        ));
    }
}
