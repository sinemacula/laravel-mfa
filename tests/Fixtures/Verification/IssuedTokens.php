<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Verification;

/**
 * What an authentication layer's sign-in result carries, as a completion seam
 * returns it to the caller of a verification.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedTokens
{
    /**
     * Constructor.
     *
     * @param  string  $accessToken
     */
    public function __construct(

        /** The access token the sign-in was issued. */
        #[\SensitiveParameter]
        public string $accessToken,
    ) {}
}
