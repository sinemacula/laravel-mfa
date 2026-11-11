<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Factors\ConfirmedFactors;
use SineMacula\Laravel\Mfa\Proofs\CountingProofs;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Fills the `mfa` namespace of the authentication context with the same eight
 * keys every time, so a policy can read them whoever is served.
 *
 * `accepted` agrees with what the gate lets through for an additional
 * verification; a gate with a freshness or stronger requirement can still
 * refuse. `factor_types` and the age come from each further proof the bound
 * check accepts beside the first factor, which is exact only under the default
 * policy.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthenticationContextContributor
{
    /** @var string */
    public const string NAMESPACE = 'mfa';

    /**
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Seams and the check are resolved on every call. */
        private Container $container,
    ) {}

    /**
     * The caller supplies the proofs from a trusted record of the sign-in,
     * never from input, and gives a pending, revoked or ended session the
     * neutral context without asking. Proofs that would not count in the proof
     * store are ignored.
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  ...$proofs
     * @return array{
     *     accepted: bool,
     *     multifactor: bool,
     *     factor_types: list<string>,
     *     level: string,
     *     phishing_resistant: bool,
     *     user_verification: bool,
     *     last_verification_age_seconds: ?int,
     *     has_confirmed_factor: bool,
     * }
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function contributeFor(MultiFactorAuthenticatable $identity, string $application, string $session, Proof ...$proofs): array
    {
        if (!$this->container->make(SubjectTypeResolver::class)->isPerson($identity) || !$this->container->make(ActiveStateResolver::class)->isActive($identity)) {
            return self::neutral();
        }

        return $this->contextOf($identity, CountingProofs::of($identity, $application, $session, $proofs));
    }

    /**
     * @formatter:off
     *
     * @return array{
     *     accepted: bool,
     *     multifactor: bool,
     *     factor_types: list<string>,
     *     level: string,
     *     phishing_resistant: bool,
     *     user_verification: bool,
     *     last_verification_age_seconds: ?int,
     *     has_confirmed_factor: bool,
     * }
     *
     * @formatter:on
     */
    public static function neutral(): array
    {
        return [
            'accepted'                      => false,
            'multifactor'                   => false,
            'factor_types'                  => [],
            'level'                         => AssuranceLevel::UNCLASSIFIED->value,
            'phishing_resistant'            => false,
            'user_verification'             => false,
            'last_verification_age_seconds' => null,
            'has_confirmed_factor'          => false,
        ];
    }

    /**
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return array{
     *     accepted: bool,
     *     multifactor: bool,
     *     factor_types: list<string>,
     *     level: string,
     *     phishing_resistant: bool,
     *     user_verification: bool,
     *     last_verification_age_seconds: ?int,
     *     has_confirmed_factor: bool,
     * }
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function contextOf(MultiFactorAuthenticatable $identity, array $proofs): array
    {
        $check       = $this->container->make(RequirementCheck::class);
        $evaluation  = $check->check(Requirement::none()->withAdditionalVerification(), ...$proofs);
        $firstFactor = self::firstFactorOf($proofs);
        $evidence    = $firstFactor === null ? [] : self::evidence($check, $firstFactor, $proofs);

        return [
            'accepted'                      => $evaluation->meetsRequirement(),
            'multifactor'                   => $evaluation->multifactor,
            'factor_types'                  => array_values(array_unique(array_map(static fn (Proof $proof): string => $proof->method, $evidence))),
            'level'                         => $evaluation->level->value,
            'phishing_resistant'            => $evaluation->phishingResistant,
            'user_verification'             => self::observedUserVerification($check, $firstFactor, $evidence),
            'last_verification_age_seconds' => self::ageOfNewest($evidence),
            'has_confirmed_factor'          => ConfirmedFactors::isHeldBy($identity, $this->container->make(Repository::class)),
        ];
    }

    /**
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactorOf(array $proofs): ?Proof
    {
        $firstFactors = array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->kind === ProofKind::FIRST_FACTOR));

        return count($firstFactors) === 1 ? $firstFactors[0] : null;
    }

    /**
     * Recovery codes count, as they meet an additional verification.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return list<\SineMacula\Laravel\Mfa\Proofs\Proof>
     */
    private static function evidence(RequirementCheck $check, Proof $firstFactor, array $proofs): array
    {
        return array_values(array_filter(
            $proofs,
            static fn (Proof $proof): bool => in_array($proof->kind, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], true)
                && $check->check(Requirement::none(), $firstFactor, $proof)->accepted,
        ));
    }

    /**
     * The first factor counts only when it supports a level.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\RequirementCheck  $check
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\Proof  $firstFactor
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $evidence
     * @return bool
     */
    private static function observedUserVerification(RequirementCheck $check, ?Proof $firstFactor, array $evidence): bool
    {
        foreach ($evidence as $proof) {
            if ($proof->properties->userVerification === true) {
                return true;
            }
        }

        return $firstFactor?->properties->userVerification === true
            && $check->check(Requirement::none(), $firstFactor)->level !== AssuranceLevel::UNCLASSIFIED;
    }

    /**
     * Whole seconds since the newest evidence; the evidence is oldest first.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $evidence
     * @return ?int
     */
    private static function ageOfNewest(array $evidence): ?int
    {
        return $evidence === [] ? null : (int) $evidence[count($evidence) - 1]->provedAt->diffInSeconds(CarbonImmutable::now());
    }
}
