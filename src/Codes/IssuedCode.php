<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;

/**
 * A newly issued code. The clear code exists only here and in the message that
 * delivers it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedCode
{
    /**
     * @param  string  $challengeId
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Challenge the code was issued for. */
        public string $challengeId,

        /** Code in clear. */
        #[\SensitiveParameter]
        public string $code,

        /** Expiry time. */
        public CarbonImmutable $expiresAt,
    ) {}
}
