<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Classifies combinations as NIST SP 800-63B-4 does, from what the proofs
 * observed.
 *
 * A factor of the first factor's channel kind is independent only when both
 * name a reference and they differ. Exactly one first factor on a known channel
 * is required; proofs bound elsewhere, made before it or dated in the future
 * count for nothing. A part is met when one combination provides it within its
 * maximum age.
 *
 * An external provider's first factor adds no level; an application that trusts
 * its provider's reported methods rebinds the policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DefaultCombinationPolicy implements CombinationPolicy
{
    /** @var list<\SineMacula\Laravel\Mfa\Enums\ProofKind> Kinds a first factor's channel can be read from. */
    private const array FIRST_FACTOR_KINDS = [ProofKind::FIRST_FACTOR, ProofKind::FIRST_FACTOR_REAUTHENTICATION];

    /** @var string */
    private const string AMR_MULTIFACTOR = 'mfa';

    /** @var string An accepted additional verification that is not multifactor. */
    private const string AMR_MULTIPLE_CHANNEL = 'mca';

    /**
     * Whether a factor on the given channel may follow the first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    #[\Override]
    public function accepts(Proof $firstFactor, Channel $factor): bool
    {
        $channel = $firstFactor->channel;

        if (!in_array($firstFactor->kind, self::FIRST_FACTOR_KINDS, true) || $channel === null || $channel->kind === ChannelKind::UNKNOWN) {
            return false;
        }

        return $factor->kind->carriesFactor() && !self::isSameChannel($channel, $factor);
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $now          = CarbonImmutable::now();
        $firstFactor  = self::firstFactor($proofs);
        $combinations = $firstFactor === null ? [] : $this->combinations($firstFactor, $proofs, $now);

        $accepted    = self::hasCombinationWhere($combinations, static fn (Combination $combination): bool => $combination->accepted);
        $multifactor = self::hasCombinationWhere($combinations, static fn (Combination $combination): bool => $combination->isMultifactor());
        $level       = self::highestLevel($combinations);

        [$met, $unmet] = self::judge($requirement, $combinations, $now);

        return new Evaluation(
            accepted: $accepted,
            multifactor: $multifactor,
            level: $level,
            phishingResistant: self::hasCombinationWhere($combinations, static fn (Combination $combination): bool => $combination->isPhishingResistant()),
            restricted: self::restrictedAt($level, $combinations),
            amr: self::amr($combinations, $accepted, $multifactor),
            met: $met,
            unmet: $unmet,
            metUntil: $unmet === [] ? self::metUntil($requirement, $combinations) : null,
            multifactorAt: self::multifactorAt($combinations),
        );
    }

    /**
     * Same kind, with the same reference or either naming none, since
     * independence then cannot be shown.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $first
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $factor
     * @return bool
     */
    private static function isSameChannel(Channel $first, Channel $factor): bool
    {
        if ($first->kind !== $factor->kind) {
            return false;
        }

        $firstReference  = $first->reference();
        $factorReference = $factor->reference();

        if ($firstReference === null || $factorReference === null) {
            return true;
        }

        return self::normalizeReference($first->kind, $firstReference)
            === self::normalizeReference($factor->kind, $factorReference);
    }

    /**
     * Email addresses compare case-insensitively.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  string  $reference
     * @return string
     */
    private static function normalizeReference(ChannelKind $kind, string $reference): string
    {
        return $kind === ChannelKind::EMAIL ? mb_strtolower($reference) : $reference;
    }

    /**
     * `null` when there is none, more than one, or its channel is unknown.
     *
     * @param  array<array-key, \SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(array $proofs): ?Proof
    {
        $firstFactors = array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->kind === ProofKind::FIRST_FACTOR));

        if (count($firstFactors) !== 1 || $firstFactors[0]->channel?->kind === ChannelKind::UNKNOWN) {
            return null;
        }

        return $firstFactors[0];
    }

    /**
     * Only proofs bound alike and made between the first factor and now count.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  array<array-key, \SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @param  \Carbon\CarbonImmutable  $now
     * @return list<\SineMacula\Laravel\Mfa\Assurance\Combination>
     */
    private function combinations(Proof $firstFactor, array $proofs, CarbonImmutable $now): array
    {
        $combinations = [];

        foreach ($proofs as $proof) {
            $counts      = self::isBoundAlike($firstFactor, $proof) && self::isMadeBetween($firstFactor, $proof, $now);
            $combination = $counts ? $this->combinationOf($firstFactor, $proof) : null;

            if ($combination === null) {
                continue;
            }

            $combinations[] = $combination;
        }

        return $combinations;
    }

    /**
     * `null` for a reauthentication on an unknown channel or a further proof
     * the policy does not accept. A recovery code has no channel to share.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return ?\SineMacula\Laravel\Mfa\Assurance\Combination
     */
    private function combinationOf(Proof $firstFactor, Proof $proof): ?Combination
    {
        $channel = $proof->channel;

        return match ($proof->kind) {
            ProofKind::FIRST_FACTOR,
            ProofKind::FIRST_FACTOR_REAUTHENTICATION => $channel?->kind === ChannelKind::UNKNOWN ? null : Combination::alone($proof),
            ProofKind::ADDITIONAL_FACTOR,
            ProofKind::RECOVERY_CODE => ($channel === null || $this->accepts($firstFactor, $channel)) ? Combination::after($firstFactor, $proof) : null,
        };
    }

    /**
     * Same identity and application as the first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return bool
     */
    private static function isBoundAlike(Proof $firstFactor, Proof $proof): bool
    {
        $first = $firstFactor->binding;
        $other = $proof->binding;

        return $first->identityType === $other->identityType
            && $first->identityKey  === $other->identityKey
            && $first->application  === $other->application;
    }

    /**
     * An earlier proof is left from a previous sign-in, and a future-dated one
     * cannot be trusted.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isMadeBetween(Proof $firstFactor, Proof $proof, CarbonImmutable $now): bool
    {
        return $proof->provedAt->greaterThanOrEqualTo($firstFactor->provedAt) && $proof->provedAt->lessThanOrEqualTo($now);
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @param  \Closure(\SineMacula\Laravel\Mfa\Assurance\Combination): bool  $answer
     * @return bool
     */
    private static function hasCombinationWhere(array $combinations, \Closure $answer): bool
    {
        foreach ($combinations as $combination) {
            if ($answer($combination)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @return \SineMacula\Laravel\Mfa\Enums\AssuranceLevel
     */
    private static function highestLevel(array $combinations): AssuranceLevel
    {
        $level = AssuranceLevel::UNCLASSIFIED;

        foreach ($combinations as $combination) {
            if (!$combination->level()->meets($level)) {
                continue;
            }

            $level = $combination->level();
        }

        return $level;
    }

    /**
     * Every combination reaching the level is restricted.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @return bool
     */
    private static function restrictedAt(AssuranceLevel $level, array $combinations): bool
    {
        if ($level === AssuranceLevel::UNCLASSIFIED) {
            return false;
        }

        foreach ($combinations as $combination) {
            if ($combination->level() === $level && !$combination->isRestricted()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Each value once in first-reported order, then `mfa` or `mca`.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @param  bool  $accepted
     * @param  bool  $multifactor
     * @return list<string>
     */
    private static function amr(array $combinations, bool $accepted, bool $multifactor): array
    {
        $amr = [];

        foreach ($combinations as $combination) {
            $amr = [...$amr, ...$combination->amr()];
        }

        if ($multifactor) {
            $amr[] = self::AMR_MULTIFACTOR;
        }

        if ($accepted && !$multifactor) {
            $amr[] = self::AMR_MULTIPLE_CHANNEL;
        }

        return array_values(array_unique($amr));
    }

    /**
     * Met and unmet parts, each in the requirement's order.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>, list<\SineMacula\Laravel\Mfa\Enums\RequirementPart>}
     */
    private static function judge(Requirement $requirement, array $combinations, CarbonImmutable $now): array
    {
        $met   = [];
        $unmet = [];

        foreach ($requirement->parts() as $part) {
            if (self::isMet($requirement, $part, $combinations, $now)) {
                $met[] = $part;

                continue;
            }

            $unmet[] = $part;
        }

        return [$met, $unmet];
    }

    /**
     * One combination provides the part within its maximum age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isMet(Requirement $requirement, RequirementPart $part, array $combinations, CarbonImmutable $now): bool
    {
        $maxAge   = $requirement->maxAge($part);
        $provides = static fn (Combination $combination): bool => self::provides($combination, $part, $requirement->minimumLevel);

        foreach ($combinations as $combination) {
            if ($combination->holdsWithin($provides, $maxAge, $now)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The freshest multifactor evidence, or `null` when none is multifactor.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @return ?\Carbon\CarbonImmutable
     */
    private static function multifactorAt(array $combinations): ?CarbonImmutable
    {
        $latest = null;

        foreach ($combinations as $combination) {
            $made = $combination->evidencedAt(static fn (Combination $candidate): bool => $candidate->isMultifactor());

            if ($made === null || ($latest !== null && $made->lessThanOrEqualTo($latest))) {
                continue;
            }

            $latest = $made;
        }

        return $latest;
    }

    /**
     * The earliest age-bounded part's lapse, or `null` when none is bounded.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @return ?\Carbon\CarbonImmutable
     */
    private static function metUntil(Requirement $requirement, array $combinations): ?CarbonImmutable
    {
        $until = null;

        foreach ($requirement->parts() as $part) {
            $maxAge = $requirement->maxAge($part);
            $held   = $maxAge === null ? null : self::partHeldUntil($requirement, $part, $maxAge, $combinations);

            if ($held === null || ($until !== null && $held->greaterThanOrEqualTo($until))) {
                continue;
            }

            $until = $held;
        }

        return $until;
    }

    /**
     * The latest time any providing combination holds the part, `$maxAge` in
     * seconds.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  int  $maxAge
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @return ?\Carbon\CarbonImmutable
     */
    private static function partHeldUntil(Requirement $requirement, RequirementPart $part, int $maxAge, array $combinations): ?CarbonImmutable
    {
        $provides = static fn (Combination $combination): bool => self::provides($combination, $part, $requirement->minimumLevel);
        $latest   = null;

        foreach ($combinations as $combination) {
            $held = $combination->heldUntil($provides, $maxAge);

            if ($held === null || ($latest !== null && $held->lessThanOrEqualTo($latest))) {
                continue;
            }

            $latest = $held;
        }

        return $latest;
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Assurance\Combination  $combination
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  ?\SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $minimumLevel
     * @return bool
     */
    private static function provides(Combination $combination, RequirementPart $part, ?AssuranceLevel $minimumLevel): bool
    {
        return match ($part) {
            RequirementPart::ADDITIONAL_VERIFICATION => $combination->accepted || $combination->isMultifactor(),
            RequirementPart::MULTIFACTOR             => $combination->isMultifactor(),
            RequirementPart::MINIMUM_LEVEL           => $minimumLevel !== null && $combination->level()->meets($minimumLevel),
            RequirementPart::PHISHING_RESISTANCE     => $combination->isPhishingResistant(),
        };
    }
}
