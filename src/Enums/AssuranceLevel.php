<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * The authenticator assurance level a combination of proofs supports, on the
 * scale NIST SP 800-63B-4 defines, or unclassified when the evidence cannot
 * support a level. Unclassified meets no level requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AssuranceLevel: string
{
    // Single-factor authentication
    case AAL1 = 'aal1';

    // Two distinct factors, or one multi-factor authenticator
    case AAL2 = 'aal2';

    // A hardware-bound, phishing-resistant multi-factor authenticator
    case AAL3 = 'aal3';

    // The evidence supports no level
    case UNCLASSIFIED = 'unclassified';

    /**
     * Unclassified meets no level.
     *
     * @param  \SineMacula\Laravel\Mfa\Enums\AssuranceLevel  $minimum
     * @return bool
     */
    public function meets(self $minimum): bool
    {
        return $this !== self::UNCLASSIFIED && $this->rank() >= $minimum->rank();
    }

    /**
     * @return int
     */
    private function rank(): int
    {
        return match ($this) {
            self::UNCLASSIFIED => 0,
            self::AAL1         => 1,
            self::AAL2         => 2,
            self::AAL3         => 3,
        };
    }
}
