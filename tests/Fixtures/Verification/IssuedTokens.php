<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Verification;

/**
 * A sign-in result a completion seam returns to the caller of a verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedTokens
{
    /**
     * @param  string  $accessToken
     */
    public function __construct(

        /** @var string */
        #[\SensitiveParameter]
        public string $accessToken,
    ) {}
}
