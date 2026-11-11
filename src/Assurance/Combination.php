<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * A first-factor proof alone, or followed by one further accepted proof. Never
 * AAL3: hardware-bound keys cannot be seen without attestation.
 *
 * An answer is as fresh as its evidence, so a fresh weaker further proof never
 * refreshes what the first factor gives on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Combination
{
    /**
     * @param  bool  $accepted
     * @param  non-empty-list<\SineMacula\Laravel\Mfa\Assurance\Authenticator>  $authenticators
     * @param  \Carbon\CarbonImmutable  $provedAt
     * @param  ?array{self, self}  $proofsAlone
     */
    private function __construct(

        /** An accepted additional verification. */
        public bool $accepted,

        /** The authenticators relied on. */
        private array $authenticators,

        /** When the completing proof was made. */
        public CarbonImmutable $provedAt,

        /** The first factor and further proof, each alone, when there is a further proof. */
        private ?array $proofsAlone = null,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return self
     */
    public static function alone(Proof $proof): self
    {
        return new self(false, [Authenticator::of($proof)], $proof->provedAt);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return self
     */
    public static function after(Proof $firstFactor, Proof $proof): self
    {
        $first   = self::alone($firstFactor);
        $further = new self(true, [Authenticator::of($proof)], $proof->provedAt);

        return new self(true, [$first->authenticators[0], $further->authenticators[0]], $proof->provedAt, [$first, $further]);
    }

    /**
     * A multi-factor authenticator, or something known with something had.
     *
     * @return bool
     */
    public function isMultifactor(): bool
    {
        if ($this->hasMultiFactorAuthenticator()) {
            return true;
        }

        return $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->knowledge)
            && $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->possession);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\AssuranceLevel
     */
    public function level(): AssuranceLevel
    {
        if ($this->isMultifactor()) {
            return AssuranceLevel::AAL2;
        }

        foreach ($this->authenticators as $authenticator) {
            if ($authenticator->establishesLevel()) {
                return AssuranceLevel::AAL1;
            }
        }

        return AssuranceLevel::UNCLASSIFIED;
    }

    /**
     * Holds a restricted authenticator and no multi-factor one.
     *
     * @return bool
     */
    public function isRestricted(): bool
    {
        return !$this->hasMultiFactorAuthenticator()
            && $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->restricted);
    }

    /**
     * @return bool
     */
    public function isPhishingResistant(): bool
    {
        return $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->phishingResistant);
    }

    /**
     * The first factor's values first.
     *
     * @return list<string>
     */
    public function amr(): array
    {
        $amr = [];

        foreach ($this->authenticators as $authenticator) {
            $amr = [...$amr, ...$authenticator->amr];
        }

        return $amr;
    }

    /**
     * Whether the answer holds on evidence no older than `$maxAge` seconds;
     * `null` allows any age.
     *
     * @param  \Closure(self): bool  $answer
     * @param  ?int  $maxAge
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    public function holdsWithin(\Closure $answer, ?int $maxAge, CarbonImmutable $now): bool
    {
        if (!$answer($this)) {
            return false;
        }

        return $maxAge === null || $this->evidenceFor($answer)->greaterThanOrEqualTo($now->subSeconds($maxAge));
    }

    /**
     * The last instant the answer holds under `$maxAge` seconds, or `null` when
     * it never does.
     *
     * @param  \Closure(self): bool  $answer
     * @param  int  $maxAge
     * @return ?\Carbon\CarbonImmutable
     */
    public function heldUntil(\Closure $answer, int $maxAge): ?CarbonImmutable
    {
        return $answer($this) ? $this->evidenceFor($answer)->addSeconds($maxAge) : null;
    }

    /**
     * When the evidence for the answer was made, or `null` when it fails.
     *
     * @param  \Closure(self): bool  $answer
     * @return ?\Carbon\CarbonImmutable
     */
    public function evidencedAt(\Closure $answer): ?CarbonImmutable
    {
        return $answer($this) ? $this->evidenceFor($answer) : null;
    }

    /**
     * The first factor's time when only it gives the answer, else the
     * completing proof's.
     *
     * @param  \Closure(self): bool  $answer
     * @return \Carbon\CarbonImmutable
     */
    private function evidenceFor(\Closure $answer): CarbonImmutable
    {
        if ($this->proofsAlone === null) {
            return $this->provedAt;
        }

        [$firstFactor, $furtherProof] = $this->proofsAlone;

        return $answer($firstFactor) && !$answer($furtherProof) ? $firstFactor->provedAt : $this->provedAt;
    }

    /**
     * @return bool
     */
    private function hasMultiFactorAuthenticator(): bool
    {
        return $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->multiFactor);
    }

    /**
     * @param  \Closure(\SineMacula\Laravel\Mfa\Assurance\Authenticator): bool  $answer
     * @return bool
     */
    private function hasAuthenticatorWhere(\Closure $answer): bool
    {
        foreach ($this->authenticators as $authenticator) {
            if ($answer($authenticator)) {
                return true;
            }
        }

        return false;
    }
}
