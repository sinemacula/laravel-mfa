<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * An enrolment grant: an opaque 256-bit random token, returned once as a secret
 * for the response, of which only the SHA-256 digest is stored. A token this
 * long needs no salt or key, as there is nothing to guess against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnrollmentGrant
{
    /** @var int How many random bytes a grant is drawn from. */
    private const int BYTES = 32;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Draw a new grant.
     *
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     *
     * @throws \Random\RandomException
     */
    public static function issue(): RevealedSecret
    {
        return new RevealedSecret(bin2hex(random_bytes(self::BYTES)));
    }

    /**
     * The digest a grant is stored and looked up under, as 64 hexadecimal
     * characters.
     *
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return string
     */
    public static function hash(#[\SensitiveParameter] RevealedSecret|string $grant): string
    {
        return hash('sha256', $grant instanceof RevealedSecret ? $grant->reveal() : $grant);
    }
}
