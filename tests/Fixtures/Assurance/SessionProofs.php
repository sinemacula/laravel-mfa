<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Assurance;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * Builds the proofs of one session for the combination policy's tests: the
 * first factors a sign-in can start with, a reauthentication with the first
 * factor, and the further proofs that can follow, each made a given number of
 * seconds before a fixed time and bound to the same identity and application
 * unless told otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionProofs
{
    /** @var string The phone number the session signed in with. */
    public const string PHONE = '+447700900123';

    /** @var string Another phone number, enrolled as an SMS factor. */
    public const string OTHER_PHONE = '+447700900456';

    /** @var string The email address the session signed in with. */
    public const string EMAIL = 'person@example.com';

    /** @var string Another email address, enrolled as an email factor. */
    public const string OTHER_EMAIL = 'other@example.com';

    /** @var string The passkey the session signed in with. */
    public const string PASSKEY = 'credential-1';

    /** @var string Another passkey, associated as a factor. */
    public const string OTHER_PASSKEY = 'credential-2';

    /** @var string The identity's type. */
    public const string IDENTITY_TYPE = 'user';

    /** @var string The identity's key. */
    public const string IDENTITY_KEY = '42';

    /** @var string The application the session is on. */
    public const string APPLICATION = 'admin';

    /** @var string The time every proof's age is measured from. */
    private const string NOW = '2026-11-01T12:00:00.000000+00:00';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The time every proof's age is measured from.
     *
     * @return \Carbon\CarbonImmutable
     */
    public static function now(): CarbonImmutable
    {
        return CarbonImmutable::parse(self::NOW);
    }

    /**
     * A password first factor.
     *
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function password(int $secondsAgo = 0): Proof
    {
        return self::firstFactor('password', new Channel(ChannelKind::PASSWORD), ObservedProperties::none(), $secondsAgo);
    }

    /**
     * A phone-code first factor, to the given phone or to an unknown one.
     *
     * @param  ?string  $phone
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function phoneCode(?string $phone = self::PHONE): Proof
    {
        return self::firstFactor('sms', new Channel(ChannelKind::SMS, $phone), ObservedProperties::none());
    }

    /**
     * An email-code first factor, to the given address.
     *
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function emailCode(string $address = self::EMAIL): Proof
    {
        return self::firstFactor('email', new Channel(ChannelKind::EMAIL, $address), ObservedProperties::none());
    }

    /**
     * A passkey first factor, with what its assertion observed.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function passkeySignIn(ObservedProperties $properties, int $secondsAgo = 0): Proof
    {
        return self::firstFactor('passkey', new Channel(ChannelKind::PASSKEY, self::PASSKEY), $properties, $secondsAgo);
    }

    /**
     * An external provider's first factor.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function externalProvider(): Proof
    {
        return self::firstFactor('oidc', new Channel(ChannelKind::EXTERNAL_PROVIDER, 'provider-1'), ObservedProperties::none());
    }

    /**
     * A first factor whose channel is not known.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function unknownFirstFactor(): Proof
    {
        return self::firstFactor('unknown', Channel::unknown(), ObservedProperties::none());
    }

    /**
     * A reauthentication with the first factor on the given channel.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function reauthentication(Channel $channel, int $secondsAgo = 0): Proof
    {
        return new Proof(
            kind: ProofKind::FIRST_FACTOR_REAUTHENTICATION,
            method: 'password',
            channel: $channel,
            reference: null,
            properties: ObservedProperties::none(),
            provedAt: self::now()->subSeconds($secondsAgo),
            binding: self::binding(Purpose::REAUTHENTICATE),
            generation: 0,
        );
    }

    /**
     * A TOTP factor's proof, bound to the given identity and application.
     *
     * @param  int  $secondsAgo
     * @param  string  $identityType
     * @param  string  $identityKey
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function totp(
        int $secondsAgo = 0,
        string $identityType = self::IDENTITY_TYPE,
        string $identityKey = self::IDENTITY_KEY,
        string $application = self::APPLICATION,
    ): Proof {
        return self::factor(
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp'),
            ObservedProperties::none(),
            $secondsAgo,
            new ProofBinding($identityType, $identityKey, $application, 'session-1', Purpose::SIGN_IN),
        );
    }

    /**
     * An SMS factor's proof, to the given phone.
     *
     * @param  string  $phone
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function sms(string $phone = self::OTHER_PHONE): Proof
    {
        return self::factor('sms', new Channel(ChannelKind::SMS, $phone), ObservedProperties::none());
    }

    /**
     * An email factor's proof, to the given address.
     *
     * @param  string  $address
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function email(string $address = self::OTHER_EMAIL): Proof
    {
        return self::factor('email', new Channel(ChannelKind::EMAIL, $address), ObservedProperties::none());
    }

    /**
     * A passkey factor's proof, with what its assertion observed.
     *
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  string  $credential
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function passkey(ObservedProperties $properties, string $credential = self::OTHER_PASSKEY, int $secondsAgo = 0): Proof
    {
        return self::factor('passkey', new Channel(ChannelKind::PASSKEY, $credential), $properties, $secondsAgo);
    }

    /**
     * A recovery code's proof.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    public static function recoveryCode(): Proof
    {
        return new Proof(
            kind: ProofKind::RECOVERY_CODE,
            method: 'recovery_code',
            channel: null,
            reference: null,
            properties: ObservedProperties::none(),
            provedAt: self::now(),
            binding: self::binding(Purpose::SIGN_IN),
            generation: 0,
        );
    }

    /**
     * What a passkey assertion observed when it verified the person: presence,
     * verification and resistance to phishing.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\KeyProtection  $keyProtection
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     */
    public static function verified(?KeyProtection $keyProtection = null): ObservedProperties
    {
        return new ObservedProperties(userPresence: true, userVerification: true, phishingResistance: true, keyProtection: $keyProtection);
    }

    /**
     * What a passkey assertion observed when it did not verify the person:
     * presence and resistance to phishing, with verification as given.
     *
     * @param  ?bool  $userVerification
     * @return \SineMacula\Laravel\Mfa\Assurance\ObservedProperties
     */
    public static function unverified(?bool $userVerification = null): ObservedProperties
    {
        return new ObservedProperties(userPresence: true, userVerification: $userVerification, phishingResistance: true);
    }

    /**
     * The binding of a proof made for the given purpose by the identity on the
     * application.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    private static function binding(Purpose $purpose): ProofBinding
    {
        return new ProofBinding(self::IDENTITY_TYPE, self::IDENTITY_KEY, self::APPLICATION, 'session-1', $purpose);
    }

    /**
     * A first factor's proof, made at sign-in.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  int  $secondsAgo
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function firstFactor(string $method, Channel $channel, ObservedProperties $properties, int $secondsAgo = 0): Proof
    {
        return new Proof(
            kind: ProofKind::FIRST_FACTOR,
            method: $method,
            channel: $channel,
            reference: null,
            properties: $properties,
            provedAt: self::now()->subSeconds($secondsAgo),
            binding: self::binding(Purpose::SIGN_IN),
            generation: 0,
        );
    }

    /**
     * An additional factor's proof, made at sign-in unless bound otherwise.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Mfa\Assurance\Channel  $channel
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @param  int  $secondsAgo
     * @param  ?\SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private static function factor(string $method, Channel $channel, ObservedProperties $properties, int $secondsAgo = 0, ?ProofBinding $binding = null): Proof
    {
        return new Proof(
            kind: ProofKind::ADDITIONAL_FACTOR,
            method: $method,
            channel: $channel,
            reference: 'factor-' . $method,
            properties: $properties,
            provedAt: self::now()->subSeconds($secondsAgo),
            binding: $binding ?? self::binding(Purpose::SIGN_IN),
            generation: 0,
        );
    }
}
