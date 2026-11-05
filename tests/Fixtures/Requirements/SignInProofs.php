<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Requirements;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * Builds the proofs of one sign-in for the requirement and freshness tests: the
 * first factors a sign-in starts with, reauthentications with the first factor,
 * and the further factors that follow, each made a given number of seconds
 * before now and bound to the identity, the application and the sign-in this
 * builder names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInProofs
{
    /** @var string The application a sign-in is on unless told otherwise. */
    public const string APPLICATION = 'web';

    /** @var string The session id a sign-in is named by unless told otherwise. */
    public const string SESSION = 'sign-in-1';

    /**
     * Constructor.
     *
     * @param  string  $identityType
     * @param  string  $identityKey
     * @param  string  $application
     * @param  string  $sessionId
     * @param  int  $generation
     */
    public function __construct(

        /** The identity's type. */
        public string $identityType = 'user',

        /** The identity's key. */
        public string $identityKey = '42',

        /** The application the sign-in is on. */
        public string $application = self::APPLICATION,

        /** The session id the sign-in is named by. */
        public string $sessionId = self::SESSION,

        /** The verification generation the proofs are made under. */
        public int $generation = 0,
    ) {}

    /**
     * The proofs of the identity's sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return self
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function of(MultiFactorAuthenticatable $identity): self
    {
        $owner = ProofOwner::of($identity);

        return new self($owner->type, $owner->key);
    }

    /**
     * The same identity's proofs on another application.
     *
     * @param  string  $application
     * @return self
     */
    public function onApplication(string $application): self
    {
        return new self($this->identityType, $this->identityKey, $application, $this->sessionId, $this->generation);
    }

    /**
     * The same identity's proofs in another sign-in.
     *
     * @param  string  $sessionId
     * @return self
     */
    public function inSession(string $sessionId): self
    {
        return new self($this->identityType, $this->identityKey, $this->application, $sessionId, $this->generation);
    }

    /**
     * Another identity's proofs on the same application and sign-in.
     *
     * @param  string  $identityKey
     * @return self
     */
    public function ofIdentity(string $identityKey): self
    {
        return new self($this->identityType, $identityKey, $this->application, $this->sessionId, $this->generation);
    }

    /**
     * The same proofs made under another verification generation.
     *
     * @param  int  $generation
     * @return self
     */
    public function underGeneration(int $generation): self
    {
        return new self($this->identityType, $this->identityKey, $this->application, $this->sessionId, $generation);
    }

    /**
     * A password first factor.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function password(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR, 'password', new Channel(ChannelKind::PASSWORD), null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * A passkey first factor, with or without observed user verification.
     *
     * @param  bool  $userVerification
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function passkey(bool $userVerification, int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR, 'passkey', new Channel(ChannelKind::PASSKEY, 'credential-1'), null, self::assertion($userVerification), $secondsAgo);
    }

    /**
     * An external provider's first factor.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function externalProvider(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR, 'oidc', new Channel(ChannelKind::EXTERNAL_PROVIDER, 'provider-1'), null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * A reauthentication with a password.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function reauthentication(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'password', new Channel(ChannelKind::PASSWORD), null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * A reauthentication with an external provider, as an adapter records the
     * provider's own reauthentication: on the provider's channel, observing
     * nothing.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function externalReauthentication(int $secondsAgo = 0): Proof
    {
        $channel = new Channel(ChannelKind::EXTERNAL_PROVIDER, 'provider-1');

        return $this->proof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'oidc', $channel, null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * A reauthentication with a passkey that observed user verification.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function passkeyReauthentication(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'passkey', new Channel(ChannelKind::PASSKEY, 'credential-1'), null, self::assertion(true), $secondsAgo);
    }

    /**
     * A TOTP factor's proof.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function totp(int $secondsAgo = 0): Proof
    {
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp');

        return $this->proof(ProofKind::ADDITIONAL_FACTOR, 'totp', $channel, 'factor-totp', ObservedProperties::none(), $secondsAgo);
    }

    /**
     * A passkey factor's proof, an additional factor of its own credential,
     * multifactor on its own when user verification was observed.
     *
     * @param  bool  $userVerification
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function passkeyFactor(bool $userVerification, int $secondsAgo = 0): Proof
    {
        $channel = new Channel(ChannelKind::PASSKEY, 'credential-2');

        return $this->proof(ProofKind::ADDITIONAL_FACTOR, 'passkey', $channel, 'factor-passkey', self::assertion($userVerification), $secondsAgo);
    }

    /**
     * An email code factor's proof, accepted after a password without being
     * multifactor.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function email(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::ADDITIONAL_FACTOR, 'email', new Channel(ChannelKind::EMAIL, 'person@example.com'), 'factor-email', ObservedProperties::none(), $secondsAgo);
    }

    /**
     * What a passkey assertion observed: presence and phishing resistance, and
     * user verification as given.
     *
     * @param  bool  $userVerification
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     */
    private static function assertion(bool $userVerification): ObservedProperties
    {
        return new ObservedProperties(userPresence: true, userVerification: $userVerification, phishingResistance: true);
    }

    /**
     * A proof of the given kind, bound to this sign-in for the purpose its kind
     * carries, or for sign-in.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\ProofKind  $kind
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  ?string  $reference
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function proof(ProofKind $kind, string $method, Channel $channel, ?string $reference, ObservedProperties $properties, int $secondsAgo): Proof
    {
        return new Proof(
            kind: $kind,
            method: $method,
            channel: $channel,
            reference: $reference,
            properties: $properties,
            provedAt: CarbonImmutable::now()->subSeconds($secondsAgo),
            binding: new ProofBinding($this->identityType, $this->identityKey, $this->application, $this->sessionId, $kind->requiredPurpose() ?? Purpose::SIGN_IN),
            generation: $this->generation,
        );
    }
}
