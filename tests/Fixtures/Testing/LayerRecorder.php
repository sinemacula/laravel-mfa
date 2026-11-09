<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use Tests\Fixtures\Seams\LayerWrittenProofStore;

/**
 * A verified sign-in recorder for a store whose sign-ins and proofs another
 * layer writes: it signs the identity in through the layer, and records each
 * proof through it, against a factor it enrols for the identity when the proof
 * names one, since the store counts a proof only while its factor is held.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LayerRecorder implements VerifiedSignInRecorder
{
    /**
     * Constructor.
     *
     * @param  \Tests\Fixtures\Seams\LayerWrittenProofStore  $layer
     */
    public function __construct(

        /** The store whose layer writes the sign-ins and proofs. */
        private LayerWrittenProofStore $layer,
    ) {}

    /**
     * Sign the identity in through the layer and make that sign-in current.
     *
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
     * Record the same evidence through the layer, against a factor the identity
     * holds when the proof names one.
     *
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
