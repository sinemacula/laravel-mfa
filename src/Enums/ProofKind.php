<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * What a proof is, so a session's proofs are kept apart by kind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ProofKind: string
{
    // The method that started the sign-in
    case FIRST_FACTOR = 'first_factor';

    // The first factor proved again on an existing session
    case FIRST_FACTOR_REAUTHENTICATION = 'first_factor_reauthentication';

    // One of the identity's enrolled factors
    case ADDITIONAL_FACTOR = 'additional_factor';

    // One code of the identity's recovery code set
    case RECOVERY_CODE = 'recovery_code';

    /**
     * Null when a proof of this kind may serve any purpose.
     *
     * @return ?\SineMacula\Laravel\Mfa\Enums\Purpose
     */
    public function requiredPurpose(): ?Purpose
    {
        return match ($this) {
            self::FIRST_FACTOR                  => Purpose::SIGN_IN,
            self::FIRST_FACTOR_REAUTHENTICATION => Purpose::REAUTHENTICATE,
            default                             => null,
        };
    }

    /**
     * A recovery code is not a factor and has no channel.
     *
     * @return bool
     */
    public function hasChannel(): bool
    {
        return $this !== self::RECOVERY_CODE;
    }
}
