<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * The further proof that reaches each level after a password, and the check
 * that a sign-in reached exactly the level asked for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class LevelEvidence
{
    /** @var string The synthetic factor an AAL1 proof names. */
    public const string EMAIL_REFERENCE = 'verified-email-factor';

    /** @var string The synthetic factor an AAL2 proof names. */
    public const string TOTP_REFERENCE = 'verified-totp-factor';

    /** @var string The synthetic factor an AAL3 proof names. */
    public const string PASSKEY_REFERENCE = 'verified-passkey-factor';

    /** @var string The synthetic address an AAL1 proof travels to. */
    private const string EMAIL_ADDRESS = 'verified@example.test';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The synthetic factor a proof of the level names.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function syntheticReference(AssuranceLevel $level): string
    {
        return match ($level) {
            AssuranceLevel::AAL1         => self::EMAIL_REFERENCE,
            AssuranceLevel::AAL2         => self::TOTP_REFERENCE,
            AssuranceLevel::AAL3         => self::PASSKEY_REFERENCE,
            AssuranceLevel::UNCLASSIFIED => throw self::unclassified(),
        };
    }

    /**
     * An email code for AAL1, a TOTP code for AAL2 and a hardware passkey for
     * AAL3, naming the factor given or the synthetic one. The email and passkey
     * channels keep their synthetic address and credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \Carbon\CarbonImmutable  $provedAt
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  int  $generation
     * @param  ?string  $reference
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     *
     * @throws \InvalidArgumentException
     */
    public static function furtherProof(AssuranceLevel $level, CarbonImmutable $provedAt, ProofBinding $binding, int $generation, ?string $reference = null): Proof
    {
        $reference ??= self::syntheticReference($level);

        [$method, $channel, $properties] = match ($level) {
            AssuranceLevel::AAL1 => ['email', new Channel(ChannelKind::EMAIL, self::EMAIL_ADDRESS), ObservedProperties::none()],
            AssuranceLevel::AAL2 => ['totp', new Channel(ChannelKind::AUTHENTICATOR_APP, $reference), ObservedProperties::none()],
            AssuranceLevel::AAL3 => [
                'passkey',
                new Channel(ChannelKind::PASSKEY, self::PASSKEY_REFERENCE),
                new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true, keyProtection: KeyProtection::HARDWARE),
            ],
            AssuranceLevel::UNCLASSIFIED => throw self::unclassified(),
        };

        return new Proof(
            kind: ProofKind::ADDITIONAL_FACTOR,
            method: $method,
            channel: $channel,
            reference: $reference,
            properties: $properties,
            provedAt: $provedAt,
            binding: $binding,
            generation: $generation,
        );
    }

    /**
     * The sign-in's proofs, read as the route gate reads them, against
     * additional verification at the level.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function evaluate(Container $container, MultiFactorAuthenticatable $identity, string $application, string $session, AssuranceLevel $level): Evaluation
    {
        $proofs = $container->make(SessionFirstFactor::class)->proofsOf($identity, $application, $session);

        $requirement = Requirement::none()->withAdditionalVerification()->withMinimumLevel($level);

        return $container->make(RequirementCheck::class)->check($requirement, ...$proofs);
    }

    /**
     * Refuses an evaluation short of or past the level, or one that made no
     * additional verification.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertReached(AssuranceLevel $level, Evaluation $evaluation): void
    {
        if ($evaluation->meetsRequirement() && ($evaluation->accepted || $evaluation->multifactor) && $evaluation->level === $level) {
            return;
        }

        $unmet  = array_map(static fn (RequirementPart $part): string => $part->value, $evaluation->unmet);
        $listed = $unmet === [] ? 'none' : implode(', ', $unmet);

        throw new \LogicException(sprintf('Requested %s with additional verification; reached %s; unmet: %s.', $level->value, $evaluation->level->value, $listed));
    }

    /**
     * @return \InvalidArgumentException
     */
    private static function unclassified(): \InvalidArgumentException
    {
        return new \InvalidArgumentException('An identity cannot be verified at the unclassified level: it supports no level.');
    }
}
