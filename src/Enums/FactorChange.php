<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * A change to an identity's factors that the bound `Contracts\FactorChangeGate`
 * authorises from an active session, named by the same operation names as the
 * freshness the package's default judges it by. A first additional factor is a
 * change of its own: with no further factor to step up with, it rests on the
 * first factor proved again rather than on a step-up.
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
     * Whether the change names the factor it is made to.
     *
     * @return bool
     */
    public function namesFactor(): bool
    {
        return $this === self::REMOVE_FACTOR;
    }

    /**
     * Whether the change authorises a grant that outlives the request, whose
     * lifetime ends when the authorisation does.
     *
     * @return bool
     */
    public function isGrant(): bool
    {
        return $this === self::ADD_FIRST_ADDITIONAL_FACTOR || $this === self::ADD_FACTOR;
    }

    /**
     * The operation whose freshness the application configures for the change,
     * or `null` for a first additional factor, which no step-up can be made
     * for.
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
