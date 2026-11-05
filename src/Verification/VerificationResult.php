<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Verification;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * How a verification ended: verified, with the proof it made, its `amr` values
 * and type, the evaluation of the session's proofs with it and whatever the
 * completion seam returned; or failed, with the reason a caller may be told and
 * the detail that stays internal. A lockout also carries the time it lifts, or
 * none when a factor or an identity is at the failure ceiling and it does not
 * lift by itself.
 *
 * A failure is a result rather than an exception, so the caller answers it as
 * it chooses; exceptions are kept for misconfiguration and server errors. The
 * detail is for events and logs only: an answer to the person carries the
 * reason, within the disclosure boundary.
 *
 * The completion may hold tokens, so it is held as a `\SensitiveParameterValue`
 * and read through `completion()`, and the proof's channel hides its full
 * destination in the same way (see `Assurance\Channel`), so neither leaves
 * through any dump (`print_r`, `var_dump`, `var_export`, an array cast, or
 * Symfony's VarDumper behind Laravel's dump helpers). JSON shows a summary, and
 * serialising a result is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class VerificationResult implements \JsonSerializable
{
    /** @var \SensitiveParameterValue What the completion seam returned, hidden from dumps. */
    private \SensitiveParameterValue $completion;

    /**
     * Constructor.
     *
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

        /** The proof the verification made, when it succeeded. */
        public ?Proof $proof = null,

        /** The evaluation of the session's proofs with the new one, when it succeeded. */
        public ?Evaluation $evaluation = null,

        /** Why the verification failed, when it did. */
        public ?FailureReason $reason = null,

        /** What happened in detail, for events and logs only, when it failed. */
        public ?string $detail = null,

        /** When the lockout lifts, for `locked` only; none at the failure ceiling. */
        public ?CarbonImmutable $lockedUntil = null,

        /** The `amr` values of this proof alone, when it succeeded; never `mfa`, which only the evaluation can report. */
        public array $amr = [],

        /** The type proved, when it succeeded: the factor's, or `recovery_code`. */
        public ?string $type = null,

        /** Whether this proof supplies or completes the multifactor evidence of the session's first factor with it. */
        public bool $refreshesMultifactor = false,

        // What the completion seam returned, opaque to this package.
        #[\SensitiveParameter]
        ?object $completion = null,
    ) {
        $this->completion = new \SensitiveParameterValue($completion);
    }

    /**
     * What a dump shows: the summary, and the internal detail of a failure;
     * never the channel's destination or the completion.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [...$this->jsonSerialize(), 'detail' => $this->detail];
    }

    /**
     * Refuse to serialise the proof's destination and the completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     */
    public function __serialize(): array
    {
        throw new \LogicException('A verification result may hold secrets, so it is never serialised.');
    }

    /**
     * Refuse to read a result back.
     *
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
     * A verification that made a proof.
     *
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
     * A verification that failed, with its internal detail and, for a lockout
     * that lifts by itself, the time it does.
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
     * The same result with what the completion seam returned.
     *
     * @param  ?object  $completion
     * @return self
     */
    public function withCompletion(#[\SensitiveParameter] ?object $completion): self
    {
        return new self($this->proof, $this->evaluation, $this->reason, $this->detail, $this->lockedUntil, $this->amr, $this->type, $this->refreshesMultifactor, $completion);
    }

    /**
     * What the completion seam returned, opaque to this package.
     *
     * @return ?object
     */
    public function completion(): ?object
    {
        /** @var ?object */
        return $this->completion->getValue();
    }

    /**
     * Whether the verification made a proof.
     *
     * @return bool
     */
    public function isVerified(): bool
    {
        return $this->proof !== null;
    }

    /**
     * Whether the verification failed.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->reason !== null;
    }

    /**
     * What JSON shows: what the caller may be told, with what the proof is
     * bound to; never the channel's destination, the completion or the internal
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
