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
 * Builds the proofs of one sign-in, each made a given number of seconds ago and
 * bound to the identity, application and sign-in this builder names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SignInProofs
{
    /** @var string */
    public const string APPLICATION = 'web';

    /** @var string */
    public const string SESSION = 'sign-in-1';

    /**
     * @param  string  $identityType
     * @param  string  $identityKey
     * @param  string  $application
     * @param  string  $sessionId
     * @param  int  $generation
     */
    public function __construct(

        /** @var string */
        public string $identityType = 'user',

        /** @var string */
        public string $identityKey = '42',

        /** @var string */
        public string $application = self::APPLICATION,

        /** @var string */
        public string $sessionId = self::SESSION,

        /** @var int */
        public int $generation = 0,
    ) {}

    /**
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
     * @param  string  $application
     * @return self
     */
    public function onApplication(string $application): self
    {
        return new self($this->identityType, $this->identityKey, $application, $this->sessionId, $this->generation);
    }

    /**
     * @param  string  $sessionId
     * @return self
     */
    public function inSession(string $sessionId): self
    {
        return new self($this->identityType, $this->identityKey, $this->application, $sessionId, $this->generation);
    }

    /**
     * @param  string  $identityKey
     * @return self
     */
    public function ofIdentity(string $identityKey): self
    {
        return new self($this->identityType, $identityKey, $this->application, $this->sessionId, $this->generation);
    }

    /**
     * @param  int  $generation
     * @return self
     */
    public function underGeneration(int $generation): self
    {
        return new self($this->identityType, $this->identityKey, $this->application, $this->sessionId, $generation);
    }

    /**
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function password(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR, 'password', new Channel(ChannelKind::PASSWORD), null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * @param  bool  $userVerification
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function passkey(bool $userVerification, int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR, 'passkey', new Channel(ChannelKind::PASSKEY, 'credential-1'), null, self::assertion($userVerification), $secondsAgo);
    }

    /**
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function externalProvider(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR, 'oidc', new Channel(ChannelKind::EXTERNAL_PROVIDER, 'provider-1'), null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function reauthentication(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'password', new Channel(ChannelKind::PASSWORD), null, ObservedProperties::none(), $secondsAgo);
    }

    /**
     * On the provider's channel, observing nothing, as an adapter records it.
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
     * Observes user verification.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function passkeyReauthentication(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::FIRST_FACTOR_REAUTHENTICATION, 'passkey', new Channel(ChannelKind::PASSKEY, 'credential-1'), null, self::assertion(true), $secondsAgo);
    }

    /**
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function totp(int $secondsAgo = 0): Proof
    {
        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp');

        return $this->proof(ProofKind::ADDITIONAL_FACTOR, 'totp', $channel, 'factor-totp', ObservedProperties::none(), $secondsAgo);
    }

    /**
     * Multifactor on its own when user verification was observed.
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
     * Accepted after a password without being multifactor.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public function email(int $secondsAgo = 0): Proof
    {
        return $this->proof(ProofKind::ADDITIONAL_FACTOR, 'email', new Channel(ChannelKind::EMAIL, 'person@example.com'), 'factor-email', ObservedProperties::none(), $secondsAgo);
    }

    /**
     * @param  bool  $userVerification
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     */
    private static function assertion(bool $userVerification): ObservedProperties
    {
        return new ObservedProperties(userPresence: true, userVerification: $userVerification, phishingResistance: true);
    }

    /**
     * Bound to this sign-in for the purpose its kind carries, or for sign-in.
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
