<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Testing;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;
use Tests\Fixtures\Seams\LayerWrittenProofStore;

/**
 * A verified sign-in recorder for a layer that holds a sign-in pending until it
 * is verified: it signs the identity in without making the sign-in current,
 * records each proof through the layer, and completes the sign-in with the
 * further proof. It keeps the time it was told the sign-in began at.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingLayerRecorder implements VerifiedSignInRecorder
{
    /** @var ?\Carbon\CarbonImmutable The time the sign-in was begun at. */
    public ?CarbonImmutable $startedAt = null;

    /**
     * Constructor.
     *
     * @param  \Tests\Fixtures\Seams\LayerWrittenProofStore  $layer
     */
    public function __construct(

        /** The store whose layer writes the sign-ins and proofs. */
        private readonly LayerWrittenProofStore $layer,
    ) {}

    /**
     * Sign the identity in through the layer, pending, and keep the time.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \Carbon\CarbonImmutable  $at
     * @return string
     */
    #[\Override]
    public function begin(MultiFactorAuthenticatable $identity, string $application, CarbonImmutable $at): string
    {
        $this->startedAt = $at;

        return $this->layer->signIn();
    }

    /**
     * Record the evidence through the layer, against a factor the identity
     * holds when the proof names one, completing the pending sign-in with the
     * further proof.
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

        if ($proof->kind !== ProofKind::ADDITIONAL_FACTOR) {
            return;
        }

        $this->layer->begin($identity, $proof->binding->application, $proof->binding->sessionId);
    }
}
