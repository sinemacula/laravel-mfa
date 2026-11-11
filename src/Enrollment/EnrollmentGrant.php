<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Opaque 256-bit enrolment grant; only its SHA-256 digest is stored, which
 * needs no key at that length.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EnrollmentGrant
{
    /** @var int Grant length, in bytes. */
    private const int BYTES = 32;

    /**
     * Disallow instantiation.
     */
    private function __construct() {}

    /**
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     *
     * @throws \Random\RandomException
     */
    public static function issue(): RevealedSecret
    {
        return new RevealedSecret(bin2hex(random_bytes(self::BYTES)));
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret|string  $grant
     * @return string
     */
    public static function hash(#[\SensitiveParameter] RevealedSecret|string $grant): string
    {
        return hash('sha256', $grant instanceof RevealedSecret ? $grant->reveal() : $grant);
    }
}
