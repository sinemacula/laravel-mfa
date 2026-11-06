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
 * Fills the `mfa` namespace of the authentication context from the session's
 * recorded proofs, with the same eight keys every time, so a policy can read
 * them whoever is served: `contributeFor()` for a named sign-in whose proofs
 * the caller supplies, the one way it is built. `Mfa::authenticationContext()`
 * reads a caller's own sign-in and its proofs from the proof store and hands
 * them to it, and an authentication layer building the context for another
 * session, or in a queued job, supplies its own.
 *
 * `accepted`, `multifactor`, `level` and `phishing_resistant` come from one
 * evaluation of an additional verification against the session's proofs.
 * `accepted` means that requirement is met, including by a first factor that is
 * a multi-factor authenticator, so what the gate lets on and what this reports
 * agree for the same requirement and proofs. A gate holding a session to a
 * freshness or a stronger requirement can still refuse.
 *
 * `factor_types`, `last_verification_age_seconds` and part of
 * `user_verification` come from the session's accepted recorded evidence: each
 * additional factor or recovery code the bound check accepts after the
 * session's one first factor. It is a probe of each proof beside the first
 * factor, exact under the default policy; a bound check may accept a pair yet
 * refuse the set, so it says what was accepted and recorded and not what a
 * policy selected. Recovery codes count, as they meet an additional
 * verification. The age is not an operation's freshness, and a multi-factor
 * first factor can read `accepted` with no age.
 *
 * A pending session, a guest, a machine, an identity that is not MFA-capable
 * and an inactive identity all have the neutral context; what a pending session
 * needs to enrol comes through the pending flow.
 *
 * Stateless: consecutive requests through one instance share no answer.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthenticationContextContributor
{
    /** @var string The namespace of the authentication context the keys go under. */
    public const string NAMESPACE = 'mfa';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the seams and the check are resolved from. */
        private Container $container,
    ) {}

    /**
     * The keys of the `mfa` namespace for a named sign-in of the identity on
     * the application, from its proofs as the caller read them.
     * `has_confirmed_factor` is a fact: whether the identity has a factor whose
     * stored status is exactly `confirmed` (see `Factors\ConfirmedFactors`). A
     * status the package does not know is no confirmed factor, though
     * `isMfaEnabled()` still holds the identity to MFA for it. Only the proofs
     * that count are read, by the rules the proof store applies (bound to the
     * identity, the application and the sign-in, made in the identity's current
     * verification generation, and not dated in the future), oldest first. The
     * caller reads them from a trusted record of that sign-in, never from
     * input, leaves out any made with a factor since removed, and gives a
     * pending, revoked or ended session, or none, the neutral context without
     * asking. A machine and an inactive identity have the neutral context.
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
     * The context of a caller the package does not serve.
     *
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
     * The keys of the `mfa` namespace for the identity on the proofs of one of
     * its sign-ins.
     *
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
     * The session's one first factor, or `null` with none or more than one.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $proofs
     * @return ?\SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactorOf(array $proofs): ?Proof
    {
        $firstFactors = array_values(array_filter($proofs, static fn (Proof $proof): bool => $proof->kind === ProofKind::FIRST_FACTOR));

        return count($firstFactors) === 1 ? $firstFactors[0] : null;
    }

    /**
     * The additional factors and recovery codes the bound check accepts after
     * the first factor, oldest first.
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
     * Whether the evidence, or a first factor that supports a level, observed
     * the person verified.
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
     * How many whole seconds ago the newest of the evidence was made, or `null`
     * without any. The evidence is oldest first, as every read of a sign-in's
     * proofs returns them.
     *
     * @param  list<\SineMacula\Laravel\Mfa\Proofs\Proof>  $evidence
     * @return ?int
     */
    private static function ageOfNewest(array $evidence): ?int
    {
        return $evidence === [] ? null : (int) $evidence[count($evidence) - 1]->provedAt->diffInSeconds(CarbonImmutable::now());
    }
}
