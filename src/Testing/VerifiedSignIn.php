<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
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
use SineMacula\Laravel\Mfa\Proofs\SignInApplication;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder;

/**
 * Arranges `actingAsVerified()`: a sign-in whose proofs were made at a given
 * time and evaluate at exactly a given level, read back as the route gate reads
 * them. References are synthetic, as nothing checks them against factor rows.
 *
 * Exactly, because at least would let a test asking for AAL1 pass a route it
 * meant to fail. Additional verification is required too, since a rejected
 * further proof still reads AAL1 from the password.
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
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Everything is resolved per call, so this holds no state. */
        private Container $container,
    ) {}

    /**
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

        $application ??= SignInApplication::of($this->container, $guardName);

        $store    = $this->container->make(ProofStore::class);
        $recorder = $this->recorder($store);
        $session  = $recorder->begin($identity, $application, $provedAt);

        $generation = VerificationGeneration::current($identity);

        if (!self::holdsFirstFactor($store, $identity, $application, $session)) {
            $recorder->record($identity, new Proof(
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

        $recorder->record($identity, self::furtherProof($level, $provedAt, self::binding($identity, $application, $session), $generation));

        self::assertCurrent($store, $identity, $application, $session);

        $this->assertReached($level, $this->evaluate($identity, $application, $session, $level));
    }

    /**
     * Refuses the unclassified level and a time in the future.
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
     * The recorder may hold the sign-in pending until the further proof, but
     * never switch to another.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return void
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private static function assertCurrent(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session): void
    {
        if ($store->currentSession($identity, $application) !== $session) {
            throw new \LogicException(sprintf('The sign-in the recorder began on [%s] is not the proof store\'s current one once its proofs are recorded.', $application));
        }
    }

    /**
     * Refuses a store already holding further proofs, as the time asked for
     * could not be honoured; only a store whose `begin()` does nothing can.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @return bool
     *
     * @throws \LogicException
     */
    private static function holdsFirstFactor(ProofStore $store, MultiFactorAuthenticatable $identity, string $application, string $session): bool
    {
        $holds = false;

        foreach ($store->proofs($identity, $application, $session) as $proof) {
            if ($proof->kind !== ProofKind::FIRST_FACTOR) {
                throw new \LogicException(sprintf('The proof store already holds further proofs for the identity on [%s], so the time cannot be honoured.', $application));
            }

            $holds = true;
        }

        return $holds;
    }

    /**
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
     * Compared by class and auth identifier.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\ProofStore  $store
     * @return \SineMacula\Laravel\Mfa\Testing\Contracts\VerifiedSignInRecorder
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function recorder(ProofStore $store): VerifiedSignInRecorder
    {
        return $this->container->bound(VerifiedSignInRecorder::class)
            ? $this->container->make(VerifiedSignInRecorder::class)
            : new ProofStoreRecorder($store);
    }

    /**
     * A guard already holding the identity keeps the context its own helper
     * arranged.
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
     * Reads the proofs as the route gate does.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $session
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $level
     * @return \SineMacula\Laravel\Mfa\Assurance\Evaluation
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    private function evaluate(MultiFactorAuthenticatable $identity, string $application, string $session, AssuranceLevel $level): Evaluation
    {
        $proofs = $this->container->make(SessionFirstFactor::class)->proofsOf($identity, $application, $session);

        $requirement = Requirement::none()->withAdditionalVerification()->withMinimumLevel($level);

        return $this->container->make(RequirementCheck::class)->check($requirement, ...$proofs);
    }

    /**
     * Refuses a level short of or past the one asked for.
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
