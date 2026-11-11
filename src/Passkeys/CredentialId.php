<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

/**
 * A WebAuthn credential id as canonical unpadded base64url (RFC 4648 section
 * 5). Other spellings are refused, not normalised, so one credential can never
 * pass as two and be both a sign-in's first and second factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class CredentialId
{
    /** @var int WebAuthn's limit, in bytes. */
    public const int MAX_BYTES = 1023;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  string  $credentialId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function canonical(#[\SensitiveParameter] string $credentialId): string
    {
        $bytes = self::decode($credentialId);

        if ($bytes === null || $bytes === '' || strlen($bytes) > self::MAX_BYTES || self::encode($bytes) !== $credentialId) {
            throw new \InvalidArgumentException('A credential id must be the canonical unpadded base64url encoding of 1 to 1023 bytes.');
        }

        return $credentialId;
    }

    /**
     * @param  string  $credentialId
     * @return bool
     */
    public static function isCanonical(#[\SensitiveParameter] string $credentialId): bool
    {
        try {
            self::canonical($credentialId);
        } catch (\InvalidArgumentException) {
            return false;
        }

        return true;
    }

    /**
     * @param  string  $bytes
     * @return string
     */
    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * SHA-256, since an id may run to 1023 bytes.
     *
     * @param  string  $credentialId
     * @return string
     */
    public static function hash(#[\SensitiveParameter] string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    /**
     * @param  string  $credentialId
     * @return ?string
     */
    private static function decode(#[\SensitiveParameter] string $credentialId): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]+$/D', $credentialId) !== 1) {
            return null;
        }

        $standard = strtr($credentialId, '-_', '+/');
        $padded   = str_pad($standard, (int) (ceil(strlen($standard) / 4) * 4), '=');
        $bytes    = base64_decode($padded, true);

        return $bytes === false ? null : $bytes;
    }
}
