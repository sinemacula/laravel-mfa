<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Assurance;

use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\KeyProtection;
use SineMacula\Laravel\Mfa\Proofs\Proof;

/**
 * One proof classified in NIST SP 800-63B-4 terms, with its RFC 8176 `amr`
 * values, from its driver-fixed channel and observed properties only.
 *
 * An email code is not out-of-band and an external provider's result cannot be
 * classified, so neither is something known or had.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Authenticator
{
    /** @var string */
    private const string AMR_PASSWORD = 'pwd';

    /** @var string */
    private const string AMR_SMS = 'sms';

    /** @var string TOTP, email or recovery code. */
    private const string AMR_ONE_TIME_CODE = 'otp';

    /** @var string */
    private const string AMR_PROOF_OF_POSSESSION = 'pop';

    /** @var string */
    private const string AMR_USER_PRESENCE = 'user';

    /** @var string */
    private const string AMR_HARDWARE_KEY = 'hwk';

    /** @var string */
    private const string AMR_SOFTWARE_KEY = 'swk';

    /**
     * @param  bool  $knowledge
     * @param  bool  $possession
     * @param  bool  $multiFactor
     * @param  bool  $restricted
     * @param  bool  $phishingResistant
     * @param  list<string>  $amr
     */
    private function __construct(

        /** Something the person knows. */
        public bool $knowledge,

        /** Something the person has. */
        public bool $possession,

        /** A multi-factor authenticator on its own. */
        public bool $multiFactor,

        /** A restricted authenticator. */
        public bool $restricted,

        /** Observed to resist phishing. */
        public bool $phishingResistant,

        /** The `amr` values the proof adds. */
        public array $amr,
    ) {}

    /**
     * A proof without a channel is a recovery code.
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
            multiFactor: $kind === ChannelKind::PASSKEY && $properties->userVerification === true,
            restricted: $kind  === ChannelKind::SMS,
            phishingResistant: $properties->phishingResistance ?? false,
            amr: self::amrOf($kind, $properties),
        );
    }

    /**
     * Something known or had.
     *
     * @return bool
     */
    public function establishesLevel(): bool
    {
        return $this->knowledge || $this->possession;
    }

    /**
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
     * The method's value, then user presence and key protection when observed.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @param  \SineMacula\Laravel\Mfa\Assurance\ObservedProperties  $properties
     * @return list<string>
     */
    private static function amrOf(?ChannelKind $kind, ObservedProperties $properties): array
    {
        $amr = [
            self::methodAmrOf($kind),
            $properties->userPresence === true ? self::AMR_USER_PRESENCE : null,
            self::keyAmrOf($properties->keyProtection),
        ];

        return array_values(array_filter($amr, static fn (?string $value): bool => $value !== null));
    }

    /**
     * `null` for a channel this package cannot classify.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Enums\ChannelKind  $kind
     * @return ?string
     */
    private static function methodAmrOf(?ChannelKind $kind): ?string
    {
        return match ($kind) {
            ChannelKind::PASSWORD => self::AMR_PASSWORD,
            ChannelKind::SMS      => self::AMR_SMS,
            ChannelKind::EMAIL,
            ChannelKind::AUTHENTICATOR_APP,
            null                 => self::AMR_ONE_TIME_CODE,
            ChannelKind::PASSKEY => self::AMR_PROOF_OF_POSSESSION,
            ChannelKind::EXTERNAL_PROVIDER,
            ChannelKind::UNKNOWN => null,
        };
    }

    /**
     * @param  ?\SineMacula\Laravel\Mfa\Enums\KeyProtection  $protection
     * @return ?string
     */
    private static function keyAmrOf(?KeyProtection $protection): ?string
    {
        return match ($protection) {
            KeyProtection::HARDWARE => self::AMR_HARDWARE_KEY,
            KeyProtection::SOFTWARE => self::AMR_SOFTWARE_KEY,
            null                    => null,
        };
    }
}
