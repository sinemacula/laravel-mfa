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
 * The package's combination policy, classifying combinations as NIST SP
 * 800-63B-4 does from what the proofs observed.
 *
 * A factor is independent of the first factor unless it shares its channel: the
 * same kind with the same destination or credential, or the same kind where
 * either names none, since independence cannot then be shown. Email addresses
 * are compared without regard to case. A first factor whose channel is unknown
 * accepts no factor.
 *
 * A session's proofs are evaluated as the combinations they form: the first
 * factor, and each reauthentication with it, on its own; and the first factor
 * followed by each further proof it accepts. The session is accepted as an
 * additional verification when any further proof is accepted, is multifactor
 * when any combination is, reaches the highest level any combination supports,
 * and is restricted when every combination at that level relies on a restricted
 * authenticator. A requirement part is met when one combination provides it
 * with its completing proof within the part's maximum age, so a fresh further
 * proof refreshes an old first factor, a fresh first factor never stands in for
 * an additional factor, and an old multi-factor first factor does not meet a
 * part that asks for a fresh proof.
 *
 * The proofs must hold exactly one first factor, on a known channel: without
 * one, or with more, nothing is accepted and no level is established. A proof
 * bound to another identity or application than the first factor counts for
 * nothing. The level never reaches AAL3, and an external provider's first
 * factor adds no level of its own, so the further proof's level applies; an
 * application that trusts its provider's reported methods rebinds the policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DefaultCombinationPolicy implements CombinationPolicy
{
    /** @var list<\SineMacula\Laravel\Mfa\Enums\ProofKind> The kinds of proof a first factor's channel can be read from. */
    private const array FIRST_FACTOR_KINDS = [ProofKind::FIRST_FACTOR, ProofKind::FIRST_FACTOR_REAUTHENTICATION];

    /** @var string The `amr` value of multifactor authentication. */
    private const string AMR_MULTIFACTOR = 'mfa';

    /** @var string The `amr` value of an accepted additional verification that is not multifactor. */
    private const string AMR_MULTIPLE_CHANNEL = 'mca';

    /**
     * Whether a factor on the given channel may serve as the further factor
     * after the first factor: the first factor is a first-factor proof on a
     * known channel, the factor's channel can carry a factor, and the two do
     * not share a channel.
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
     * Evaluate the session's proofs against a requirement.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     */
    #[\Override]
    public function evaluate(Requirement $requirement, Proof ...$proofs): Evaluation
    {
        $firstFactor  = self::firstFactor($proofs);
        $combinations = $firstFactor === null ? [] : $this->combinations($firstFactor, $proofs);

        $accepted    = self::hasCombinationWhere($combinations, static fn (Combination $combination): bool => $combination->accepted);
        $multifactor = self::hasCombinationWhere($combinations, static fn (Combination $combination): bool => $combination->isMultifactor());
        $level       = self::highestLevel($combinations);

        [$met, $unmet] = self::judge($requirement, $combinations, CarbonImmutable::now());

        return new Evaluation(
            accepted: $accepted,
            multifactor: $multifactor,
            level: $level,
            phishingResistant: self::hasCombinationWhere($combinations, static fn (Combination $combination): bool => $combination->isPhishingResistant()),
            restricted: self::restrictedAt($level, $combinations),
            amr: self::amr($combinations, $accepted, $multifactor),
            met: $met,
            unmet: $unmet,
        );
    }

    /**
     * Whether a first factor's channel and a factor's channel are the same: the
     * same kind, with the same destination or credential, or with either naming
     * none.
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

        if ($first->reference === null || $factor->reference === null) {
            return true;
        }

        return self::normalizeReference($first->kind, $first->reference)
            === self::normalizeReference($factor->kind, $factor->reference);
    }

    /**
     * A channel's destination or credential in the form two channels of its
     * kind are compared in: an email address without regard to case, anything
     * else exactly as given.
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
     * The session's one first factor on a known channel, or `null` when there
     * is none, more than one, or its channel is unknown.
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
     * The combinations the session's proofs form after the first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  array<array-key, \SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Assurance\Combination>
     */
    private function combinations(Proof $firstFactor, array $proofs): array
    {
        $combinations = [];

        foreach ($proofs as $proof) {
            $combination = self::isBoundAlike($firstFactor, $proof) ? $this->combinationOf($firstFactor, $proof) : null;

            if ($combination === null) {
                continue;
            }

            $combinations[] = $combination;
        }

        return $combinations;
    }

    /**
     * The combination a proof forms after the first factor: a first-factor
     * proof on its own, or a further proof the policy accepts after the first
     * factor; `null` for a reauthentication on an unknown channel or a further
     * proof that shares the first factor's channel. A recovery code has no
     * channel to share.
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
     * Whether a proof is bound to the same identity and application as the
     * first factor.
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
     * Whether the given answer holds for any of the combinations.
     *
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
     * The highest level any combination supports, or unclassified when none
     * supports one.
     *
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
     * Whether the level relies on a restricted authenticator: it is a level,
     * and every combination that reaches it is restricted.
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
     * The `amr` values of every combination, each once in the order first
     * reported, then `mfa` for multifactor authentication or `mca` for an
     * accepted additional verification that is not.
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
     * The parts of the requirement the combinations meet, and those they do
     * not, each in the requirement's order.
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
     * Whether one combination provides the part with its completing proof
     * within the part's maximum age.
     *
     * @param  \SineMacula\Laravel\Mfa\Requirements\Requirement  $requirement
     * @param  \SineMacula\Laravel\Mfa\Enums\RequirementPart  $part
     * @param  list<\SineMacula\Laravel\Mfa\Assurance\Combination>  $combinations
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isMet(Requirement $requirement, RequirementPart $part, array $combinations, CarbonImmutable $now): bool
    {
        foreach ($combinations as $combination) {
            if ($combination->isWithin($requirement->maxAge($part), $now) && self::provides($combination, $part, $requirement->minimumLevel)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a combination provides a part: an additional verification by
     * being accepted or multifactor, multifactor authentication, the minimum
     * level, or phishing resistance.
     *
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
