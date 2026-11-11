<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * Where a proof travels or lives. Factors sharing a channel are not
 * independent, and an unknown first-factor channel establishes no level.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ChannelKind: string
{
    // A password, known to the person
    case PASSWORD = 'password';

    // A code sent by SMS to a phone number
    case SMS = 'sms';

    // A code sent by email to an address
    case EMAIL = 'email';

    // A TOTP authenticator holding a shared secret
    case AUTHENTICATOR_APP = 'authenticator_app';

    // A WebAuthn credential
    case PASSKEY = 'passkey';

    // An external identity provider's verified result
    case EXTERNAL_PROVIDER = 'external_provider';

    // Not known, or not supplied by a trusted source
    case UNKNOWN = 'unknown';

    /**
     * Whether the channel may name its destination or credential.
     *
     * @return bool
     */
    public function takesReference(): bool
    {
        return match ($this) {
            self::PASSWORD,
            self::UNKNOWN => false,
            default       => true,
        };
    }

    /**
     * A password and an unknown channel belong to first factors only.
     *
     * @return bool
     */
    public function carriesFactor(): bool
    {
        return match ($this) {
            self::PASSWORD,
            self::UNKNOWN => false,
            default       => true,
        };
    }
}
