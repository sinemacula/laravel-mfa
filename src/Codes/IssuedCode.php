<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Codes;

use Carbon\CarbonImmutable;

/**
 * A code just issued for a challenge: the challenge's id, the code in clear,
 * which exists only here and in the message that delivers it, and when it stops
 * working.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedCode
{
    /**
     * Constructor.
     *
     * @param  string  $challengeId
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The challenge the code was issued for. */
        public string $challengeId,

        /** The code, in clear. */
        #[\SensitiveParameter]
        public string $code,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,
    ) {}
}
