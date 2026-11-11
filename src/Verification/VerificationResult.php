<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * How a verification ended; a failure is a result, not an exception, and its
 * detail is for events and logs only. Secrets never leave it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerificationResult implements \JsonSerializable
{
    /** @var \SensitiveParameterValue What the completion seam returned; it may hold tokens. */
    private \SensitiveParameterValue $completion;

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  ?\SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @param  ?\SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  ?string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @param  list<string>  $amr
     * @param  ?string  $type
     * @param  bool  $refreshesMultifactor
     * @param  ?object  $completion
     */
    private function __construct(

        /** Set when the verification succeeded. */
        public ?Proof $proof = null,

        /** The session's proofs evaluated with the new one, on success. */
        public ?Evaluation $evaluation = null,

        /** Set when the verification failed. */
        public ?FailureReason $reason = null,

        /** For events and logs only. */
        public ?string $detail = null,

        /** When the lockout lifts, for `locked` only; none at the failure ceiling. */
        public ?CarbonImmutable $lockedUntil = null,

        /** This proof's `amr` values alone; never `mfa`, which only the evaluation reports. */
        public array $amr = [],

        /** The factor's type, or `recovery_code`, on success. */
        public ?string $type = null,

        /** Whether this proof supplies or completes the first factor's multifactor evidence. */
        public bool $refreshesMultifactor = false,

        // What the completion seam returned, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * The summary and a failure's detail; never the destination or the
     * completion.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [...$this->jsonSerialize(), 'detail' => $this->detail];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    public function __serialize(): array
    {
        throw new \LogicException('A verification result may hold secrets, so it is never serialised.');
    }

    /**
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A verification result may hold secrets, so it is never serialised.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @param  list<string>  $amr
     * @param  string  $type
     * @param  bool  $refreshesMultifactor
     * @return self
     */
    public static function verified(Proof $proof, Evaluation $evaluation, array $amr, string $type, bool $refreshesMultifactor = false): self
    {
        return new self(proof: $proof, evaluation: $evaluation, amr: $amr, type: $type, refreshesMultifactor: $refreshesMultifactor);
    }

    /**
     * Only a `locked` failure carries the time its lockout lifts.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  ?\Carbon\CarbonImmutable  $lockedUntil
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function failed(FailureReason $reason, string $detail, ?CarbonImmutable $lockedUntil = null): self
    {
        if (trim($detail) === '') {
            throw new \InvalidArgumentException('The detail of a failed verification must not be blank.');
        }

        if ($reason !== FailureReason::LOCKED && $lockedUntil !== null) {
            throw new \InvalidArgumentException(sprintf('Only a failure of reason [locked] carries the time a lockout lifts, not [%s].', $reason->value));
        }

        return new self(reason: $reason, detail: $detail, lockedUntil: $lockedUntil);
    }

    /**
     * @param  ?object  $completion
     * @return self
     */
    public function withCompletion(#[\SensitiveParameter] ?object $completion): self
    {
        return new self($this->proof, $this->evaluation, $this->reason, $this->detail, $this->lockedUntil, $this->amr, $this->type, $this->refreshesMultifactor, $completion);
    }

    /**
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }

    /**
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->proof !== null;
    }

    /**
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->reason !== null;
    }

    /**
     * What a caller may be told; never the destination, the completion or the
     * detail.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'verified'              => $this->isVerified(),
            'reason'                => $this->reason?->value,
            'locked_until'          => $this->lockedUntil?->toIso8601String(),
            'type'                  => $this->type,
            'amr'                   => $this->amr,
            'kind'                  => $this->proof?->kind->value,
            'reference'             => $this->proof?->reference,
            'challenge_id'          => $this->proof?->challengeId,
            'proved_at'             => $this->proof?->provedAt->toIso8601String(),
            'binding'               => $this->proof?->binding->toArray(),
            'evaluation'            => $this->evaluation?->toArray(),
            'refreshes_multifactor' => $this->refreshesMultifactor,
        ];
    }
}
