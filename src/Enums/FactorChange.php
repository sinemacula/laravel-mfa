<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * A change to an identity's factors that `Contracts\FactorChangeGate`
 * authorises. A first additional factor has no factor to step up with, so it
 * rests on the first factor proved again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorChange: string
{
    // Enrolling the identity's first additional factor
    case ADD_FIRST_ADDITIONAL_FACTOR = 'mfa.add_first_additional_factor';

    // Enrolling a further factor beside a confirmed one
    case ADD_FACTOR = 'mfa.add_factor';

    // Removing a factor
    case REMOVE_FACTOR = 'mfa.remove_factor';

    // Generating a new recovery code set
    case GENERATE_RECOVERY_CODES = 'mfa.generate_recovery_codes';

    /**
     * @return bool
     */
    public function namesFactor(): bool
    {
        return $this === self::REMOVE_FACTOR;
    }

    /**
     * Whether the change authorises a grant that outlives the request.
     *
     * @return bool
     */
    public function isGrant(): bool
    {
        return $this === self::ADD_FIRST_ADDITIONAL_FACTOR || $this === self::ADD_FACTOR;
    }

    /**
     * Null for a first additional factor, which no step-up can be made for.
     *
     * @return ?\SineMacula\Laravel\Mfa\Enums\Operation
     */
    public function operation(): ?Operation
    {
        return match ($this) {
            self::ADD_FIRST_ADDITIONAL_FACTOR => null,
            self::ADD_FACTOR                  => Operation::ADD_FACTOR,
            self::REMOVE_FACTOR               => Operation::REMOVE_FACTOR,
            self::GENERATE_RECOVERY_CODES     => Operation::GENERATE_RECOVERY_CODES,
        };
    }
}
