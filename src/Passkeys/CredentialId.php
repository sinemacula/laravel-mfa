<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Passkeys;

/**
 * A WebAuthn credential id as this package names it: the canonical unpadded
 * base64url encoding of its bytes (RFC 4648, section 5), compared exactly, case
 * included. Any other encoding of the same bytes (padded, the standard
 * alphabet, stray bits in the last character) is refused rather than
 * normalised, so two spellings of one credential can never pass as two, nor
 * slip past the rule that the passkey which started a sign-in is never its
 * second factor.
 *
 * An association record finds a credential by the SHA-256 hex digest of that
 * string, since a credential id may run to 1023 bytes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class CredentialId
{
    /** @var int The longest credential id WebAuthn allows, in bytes. */
    public const int MAX_BYTES = 1023;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The credential id, refused with an `InvalidArgumentException` unless it
     * is the canonical unpadded base64url encoding of 1 to 1023 bytes.
     *
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
     * Whether the credential id is in its canonical form.
     *
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
     * The canonical encoding of the bytes.
     *
     * @param  string  $bytes
     * @return string
     */
    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * The digest an association finds the canonical credential id by.
     *
     * @param  string  $credentialId
     * @return string
     */
    public static function hash(#[\SensitiveParameter] string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    /**
     * The bytes an unpadded base64url string encodes, or `null` when it is not
     * one.
     *
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
