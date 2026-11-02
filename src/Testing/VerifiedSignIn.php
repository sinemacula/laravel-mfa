<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\Evaluation;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\RequirementCheck;
use SineMacula\Laravel\Mfa\Enums\AssuranceLevel;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Enums\RequirementPart;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;

/**
 * Arranges what `Concerns\InteractsWithMfa::actingAsVerified()` promises: an
 * identity acting on a guard with a sign-in the proof store holds, whose proofs
 * were made at a given time and evaluate at exactly a given level.
 *
 * The arguments are checked before anything changes. The proofs carry synthetic
 * references, since nothing judges a reference against factor rows when they
 * are read. There is one table of further proofs and no branch on a level: the
 * bound combination policy judges the evidence, and the outcome is read back
 * through the same `SessionFirstFactor::proofs()` and `RequirementCheck` the
 * route gate uses.
 *
 * It has to be exactly the level because this builds a fixture: at least the
 * level would let a test asking for AAL1 pass a route it meant to fail. It asks
 * for additional verification as well, because the level alone reads AAL1 from
 * the password when the further proof was rejected.
 *
 * Stateless: everything is resolved on every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class VerifiedSignIn
{
    /** @var string The synthetic factor an AAL1 proof names. */
    public const string EMAIL_REFERENCE = 'verified-email-factor';

    /** @var string The synthetic address an AAL1 proof travels to. */
    private const string EMAIL_ADDRESS = 'verified@example.test';

    /** @var string The synthetic factor an AAL2 proof names. */
    private const string TOTP_REFERENCE = 'verified-totp-factor';

    /** @var string The synthetic factor an AAL3 proof names. */
    private const string PASSKEY_REFERENCE = 'verified-passkey-factor';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The container the guard, the store and the check are resolved from. */
        private Container $container,
    ) {}

    /**
     * Act as the identity, verified at the time and level.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?\DateTimeInterface  $at
     * @param  ?string  $guard
     * @param  ?string  $application
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\ProofRefusedException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public function act(MultiFactorAuthenticatable $identity, AssuranceLevel $level, ?\DateTimeInterface $at, ?string $guard, ?string $application): void
    {
        $provedAt = self::checkedTime($level, $at);

        $guardName = $this->actOnGuard($identity, $guard);

        $application ??= $this->container->make(ProofService::class)->applicationFor($guardName);

        $store   = $this->container->make(ProofStore::class);
        $session = self::begin($store, $identity, $application);

        $generation = VerificationGeneration::current($identity);

        if (!self::holdsFirstFactor($store, $identity, $application)) {
            $store->record(new Proof(
                kind: ProofKind::FIRST_FACTOR,
                method: 'password',
                channel: new Channel(ChannelKind::PASSWORD),
                reference: null,
                properties: ObservedProperties::none(),
                provedAt: $provedAt,
                binding: self::binding($identity, $application, $session),
                generation: $generation,
            ));
        }

        $store->record(self::furtherProof($level, $provedAt, self::binding($identity, $application, $session), $generation));

        $this->assertReached($level, $this->evaluate($identity, $application, $level));
    }

    /**
     * The time the proofs are made at, refusing a level no proof can be made at
     * and a time that has not come.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  ?\DateTimeInterface  $at
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private static function checkedTime(AssuranceLevel $level, ?\DateTimeInterface $at): CarbonImmutable
    {
        if ($level === AssuranceLevel::UNCLASSIFIED) {
            throw new \InvalidArgumentException('An identity cannot be verified at the unclassified level: it supports no level.');
        }

        $now = CarbonImmutable::now();

        if ($at === null) {
            return $now;
        }

        $provedAt = CarbonImmutable::instance($at);

        if ($provedAt->greaterThan($now)) {
            throw new \InvalidArgumentException('An identity cannot be verified in the future: a proof made after now does not count.');
        }

        return $provedAt;
    }

    /**
     * Begin a new sign-in and name it, refusing a store that knows of none.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return string
     *
     * @throws \LogicException
     */
    private static function begin(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): string
    {
        $store->begin($identity, $application, Str::lower((string) Str::ulid()));

        $session = $store->currentSession($identity, $application);

        if ($session === null) {
            throw new \LogicException(sprintf('The proof store knows of no sign-in on [%s]: a store whose begin() does nothing needs its session arranged first.', $application));
        }

        return $session;
    }

    /**
     * Whether the store already holds a first factor, which is kept, refusing
     * one holding anything further, since the time asked for could not be
     * honoured. The shipped store has just cleared; this bites a store whose
     * `begin()` does nothing.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return bool
     *
     * @throws \LogicException
     */
    private static function holdsFirstFactor(ProofStore $store, MultiFactorAuthenticatable $identity, string $application): bool
    {
        $holds = false;

        foreach ($store->proofs($identity, $application) as $proof) {
            if ($proof->kind !== ProofKind::FIRST_FACTOR) {
                throw new \LogicException(sprintf('The proof store already holds further proofs for the identity on [%s], so the time cannot be honoured.', $application));
            }

            $holds = true;
        }

        return $holds;
    }

    /**
     * The further proof of a level, on the evidence that level is made of.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \Carbon\CarbonImmutable  $provedAt
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  int  $generation
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function furtherProof(AssuranceLevel $level, CarbonImmutable $provedAt, ProofBinding $binding, int $generation): Proof
    {
        [$method, $channel, $reference, $properties] = match ($level) {
            AssuranceLevel::AAL1 => ['email', new Channel(ChannelKind::EMAIL, self::EMAIL_ADDRESS), self::EMAIL_REFERENCE, ObservedProperties::none()],
            AssuranceLevel::AAL3 => [
                'passkey',
                new Channel(ChannelKind::PASSKEY, self::PASSKEY_REFERENCE),
                self::PASSKEY_REFERENCE,
                new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true, keyProtection: KeyProtection::HARDWARE),
            ],
            default => ['totp', new Channel(ChannelKind::AUTHENTICATOR_APP, self::TOTP_REFERENCE), self::TOTP_REFERENCE, ObservedProperties::none()],
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
     * What a proof of the sign-in is bound to.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function binding(MultiFactorAuthenticatable $identity, string $application, string $session): ProofBinding
    {
        $owner = ProofOwner::of($identity);

        return new ProofBinding($owner->type, $owner->key, $application, $session, Purpose::SIGN_IN);
    }

    /**
     * Whether the guard already holds this identity, by its class and its auth
     * identifier.
     *
     * @param  \Illuminate\Contracts\Auth\Guard  $guard
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    private static function holds(Guard $guard, MultiFactorAuthenticatable $identity): bool
    {
        if (!$guard->hasUser()) {
            return false;
        }

        $user = $guard->user();

        return $user !== null && $user::class === $identity::class && $user->getAuthIdentifier() === $identity->getAuthIdentifier();
    }

    /**
     * Make the guard the default, acting as the identity: a guard already
     * holding it is not given it again, so a context arranged by the guard's
     * own helper stays.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  ?string  $guard
     * @return string
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function actOnGuard(MultiFactorAuthenticatable $identity, ?string $guard): string
    {
        $auth = $this->container->make(AuthManager::class);
        $name = $guard ?? $auth->getDefaultDriver();

        if ($identity instanceof Model) {
            $identity->wasRecentlyCreated = false;
        }

        $authGuard = $auth->guard($name);

        if (!self::holds($authGuard, $identity)) {
            $authGuard->setUser($identity);
        }

        $auth->shouldUse($name);

        return $name;
    }

    /**
     * Evaluate the sign-in's proofs as the gate reads them, against the level
     * and additional verification.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function evaluate(MultiFactorAuthenticatable $identity, string $application, AssuranceLevel $level): Evaluation
    {
        $proofs = $this->container->make(SessionFirstFactor::class)->proofs($identity, $application);

        $requirement = Requirement::none()->withAdditionalVerification()->withMinimumLevel($level);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs);
    }

    /**
     * Refuse a sign-in that fell short of the level or went past it.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @param  \SineMacula\Laravel\Mfa\Assurance\Evaluation  $evaluation
     * @return void
     *
     * @throws \LogicException
     */
    private function assertReached(AssuranceLevel $level, Evaluation $evaluation): void
    {
        if ($evaluation->meetsRequirement() && $evaluation->level === $level) {
            return;
        }

        $unmet  = array_map(static fn (RequirementPart $part): string => $part->value, $evaluation->unmet);
        $listed = $unmet === [] ? 'none' : implode(', ', $unmet);

        throw new \LogicException(sprintf('Requested %s with additional verification; reached %s; unmet: %s.', $level->value, $evaluation->level->value, $listed));
    }
}
