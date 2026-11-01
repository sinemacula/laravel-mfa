<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * What one proof shows as an authenticator, in NIST SP 800-63B-4's terms:
 * whether it is something the person knows or has, whether it is a multi-factor
 * authenticator on its own, whether it is restricted, whether it resisted
 * phishing, and the RFC 8176 `amr` values it adds.
 *
 * The answers come from the channel the proof travelled on, which the driver
 * fixes, and from the properties the proof actually observed, never from a
 * type name or from configuration. A password is something known; an SMS code,
 * a TOTP code, a recovery code and a passkey are something had; a passkey whose
 * assertion was observed to verify the person is a multi-factor authenticator.
 * An email code is not an out-of-band authenticator, and an external provider's
 * result says nothing this package can classify, so neither is either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Authenticator
{
    /** @var string The `amr` value of a password. */
    private const string AMR_PASSWORD = 'pwd';

    /** @var string The `amr` value of a code sent by SMS. */
    private const string AMR_SMS = 'sms';

    /** @var string The `amr` value of a one-time code: TOTP, email or recovery code. */
    private const string AMR_ONE_TIME_CODE = 'otp';

    /** @var string The `amr` value of a proof of possession of a key. */
    private const string AMR_PROOF_OF_POSSESSION = 'pop';

    /** @var string The `amr` value of observed user presence. */
    private const string AMR_USER_PRESENCE = 'user';

    /** @var string The `amr` value of an observed hardware-protected key. */
    private const string AMR_HARDWARE_KEY = 'hwk';

    /** @var string The `amr` value of an observed software-protected key. */
    private const string AMR_SOFTWARE_KEY = 'swk';

    /**
     * Constructor.
     *
     * @param  bool  $knowledge
     * @param  bool  $possession
     * @param  bool  $multiFactor
     * @param  bool  $restricted
     * @param  bool  $phishingResistant
     * @param  list<string>  $amr
     */
    private function __construct(

        /** Whether the proof is something the person knows. */
        public bool $knowledge,

        /** Whether the proof is something the person has. */
        public bool $possession,

        /** Whether the proof is a multi-factor authenticator on its own. */
        public bool $multiFactor,

        /** Whether the proof is a restricted authenticator. */
        public bool $restricted,

        /** Whether the proof was observed to resist phishing. */
        public bool $phishingResistant,

        /** The `amr` values the proof adds. */
        public array $amr,
    ) {}

    /**
     * What the given proof shows as an authenticator. A proof without a
     * channel is a recovery code.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return self
     */
    public static function of(Proof $proof): self
    {
        $kind       = $proof->channel?->kind;
        $properties = $proof->properties;

        return new self(
            knowledge: $kind === ChannelKind::PASSWORD,
            possession: self::isPossession($kind),
            multiFactor: $kind                                 === ChannelKind::PASSKEY && $properties->userVerification === true,
            restricted: $kind                                  === ChannelKind::SMS,
            phishingResistant: $properties->phishingResistance === true,
            amr: self::amrOf($kind, $properties),
        );
    }

    /**
     * Whether the proof can establish a level: something known or had.
     *
     * @return bool
     */
    public function establishesLevel(): bool
    {
        return $this->knowledge || $this->possession;
    }

    /**
     * Whether a proof on a channel of the given kind, or a recovery code when
     * there is none, is something the person has.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return bool
     */
    private static function isPossession(?ChannelKind $kind): bool
    {
        return match ($kind) {
            ChannelKind::SMS,
            ChannelKind::AUTHENTICATOR_APP,
            ChannelKind::PASSKEY,
            null    => true,
            default => false,
        };
    }

    /**
     * The `amr` values of a proof: its method's, then user presence and key
     * protection, each only when it was observed.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @return list<string>
     */
    private static function amrOf(?ChannelKind $kind, ObservedProperties $properties): array
    {
        $amr = [];

        $method = match ($kind) {
            ChannelKind::PASSWORD => self::AMR_PASSWORD,
            ChannelKind::SMS      => self::AMR_SMS,
            ChannelKind::EMAIL,
            ChannelKind::AUTHENTICATOR_APP,
            null                 => self::AMR_ONE_TIME_CODE,
            ChannelKind::PASSKEY => self::AMR_PROOF_OF_POSSESSION,
            ChannelKind::EXTERNAL_PROVIDER,
            ChannelKind::UNKNOWN => null,
        };

        if ($method !== null) {
            $amr[] = $method;
        }

        if ($properties->userPresence === true) {
            $amr[] = self::AMR_USER_PRESENCE;
        }

        $key = match ($properties->keyProtection) {
            KeyProtection::HARDWARE => self::AMR_HARDWARE_KEY,
            KeyProtection::SOFTWARE => self::AMR_SOFTWARE_KEY,
            null                    => null,
        };

        if ($key !== null) {
            $amr[] = $key;
        }

        return $amr;
    }
}
