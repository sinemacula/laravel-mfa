<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * The keys of the `mfa` authentication context, with their namespace.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ContextKey: string
{
    // The session meets an additional verification
    case ACCEPTED = 'mfa.accepted';

    // The session's proofs are multifactor authentication
    case MULTIFACTOR = 'mfa.multifactor';

    // The types of its evidence, each once, oldest first
    case FACTOR_TYPES = 'mfa.factor_types';

    // The assurance level its proofs support
    case LEVEL = 'mfa.level';

    // Whether they are phishing-resistant
    case PHISHING_RESISTANT = 'mfa.phishing_resistant';

    // Whether the person was observed to verify
    case USER_VERIFICATION = 'mfa.user_verification';

    // Whole seconds since the newest evidence, or null without any
    case LAST_VERIFICATION_AGE_SECONDS = 'mfa.last_verification_age_seconds';

    // Whether the identity has a confirmed factor
    case HAS_CONFIRMED_FACTOR = 'mfa.has_confirmed_factor';

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ContextValueType
     */
    public function type(): ContextValueType
    {
        return match ($this) {
            self::FACTOR_TYPES                  => ContextValueType::LIST,
            self::LEVEL                         => ContextValueType::STRING,
            self::LAST_VERIFICATION_AGE_SECONDS => ContextValueType::NUMBER,
            default                             => ContextValueType::BOOL,
        };
    }
}
