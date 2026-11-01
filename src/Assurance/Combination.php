<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * One way a session's proofs can satisfy a requirement: a first-factor proof on
 * its own, or the first factor followed by one further proof the policy
 * accepted after it.
 *
 * A combination supports AAL2 when it holds a multi-factor authenticator, or
 * something known with something had; AAL1 when it holds anything that can
 * establish a level; and no level otherwise. It never supports AAL3, which
 * needs hardware-bound keys that cannot be seen without attestation. It is
 * restricted when it relies on a restricted authenticator, which a multi-factor
 * authenticator makes unnecessary.
 *
 * Its time is that of the proof that completes it: a further proof refreshes
 * the combination it completes, and a first factor made again never stands in
 * for one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Combination
{
    /**
     * Constructor.
     *
     * @param  bool  $accepted
     * @param  non-empty-list<\SineMacula\Laravel\Mfa\Assurance\Authenticator>  $authenticators
     * @param  \Carbon\CarbonImmutable  $provedAt
     */
    private function __construct(

        /** Whether the combination is an accepted additional verification. */
        public bool $accepted,

        /** The authenticators the combination relies on. */
        private array $authenticators,

        /** When the proof that completes the combination was made. */
        public CarbonImmutable $provedAt,
    ) {}

    /**
     * The combination of a first-factor proof on its own, which is not an
     * additional verification.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return self
     */
    public static function alone(Proof $proof): self
    {
        return new self(false, [Authenticator::of($proof)], $proof->provedAt);
    }

    /**
     * The combination of the first factor followed by a further proof the
     * policy accepted after it.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return self
     */
    public static function after(Proof $firstFactor, Proof $proof): self
    {
        return new self(true, [Authenticator::of($firstFactor), Authenticator::of($proof)], $proof->provedAt);
    }

    /**
     * Whether the combination is multifactor authentication: a multi-factor
     * authenticator, or something known with something had.
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
     * The level the combination supports.
     *
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
     * Whether the combination relies on a restricted authenticator: it holds
     * one, and no multi-factor authenticator carries the level without it.
     *
     * @return bool
     */
    public function isRestricted(): bool
    {
        return !$this->hasMultiFactorAuthenticator()
            && $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->restricted);
    }

    /**
     * Whether a proof of the combination was observed to resist phishing.
     *
     * @return bool
     */
    public function isPhishingResistant(): bool
    {
        return $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->phishingResistant);
    }

    /**
     * The `amr` values of the combination's proofs, the first factor's first.
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
     * Whether the proof that completes the combination is no older than the
     * given maximum age in seconds at the given time, where `null` allows any
     * age. A proof made after the given time is not within any maximum age.
     *
     * @param  ?int  $maxAge
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    public function isWithin(?int $maxAge, CarbonImmutable $now): bool
    {
        if ($maxAge === null) {
            return true;
        }

        return $this->provedAt->lessThanOrEqualTo($now) && $this->provedAt->greaterThanOrEqualTo($now->subSeconds($maxAge));
    }

    /**
     * Whether the combination holds a multi-factor authenticator.
     *
     * @return bool
     */
    private function hasMultiFactorAuthenticator(): bool
    {
        return $this->hasAuthenticatorWhere(static fn (Authenticator $authenticator): bool => $authenticator->multiFactor);
    }

    /**
     * Whether the given answer holds for any of the combination's
     * authenticators.
     *
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
