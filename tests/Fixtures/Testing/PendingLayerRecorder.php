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
 * Records through a layer that holds a sign-in pending until the further proof
 * completes it, keeping the time the sign-in began.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingLayerRecorder implements VerifiedSignInRecorder
{
    /** @var ?\Carbon\CarbonImmutable */
    public ?CarbonImmutable $startedAt = null;

    /**
     * @param  \Tests\Fixtures\Seams\LayerWrittenProofStore  $layer
     */
    public function __construct(

        /** Its layer writes the sign-ins and proofs. */
        private readonly LayerWrittenProofStore $layer,
    ) {}

    /**
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
