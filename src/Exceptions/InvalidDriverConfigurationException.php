<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Exceptions;

/**
 * Invalid driver configuration exception.
 *
 * Thrown when a factor driver is instantiated with configuration that cannot
 * produce a sound runtime — zero-length codes, alphabets with fewer than two
 * characters, SMS templates missing their `:code` placeholder, batch requests
 * larger than the configured code space, and so on. Surfacing the fault as a
 * typed exception at construction time lets consumers distinguish
 * driver-configuration bugs from generic argument errors when they want typed
 * handling; inheriting `\InvalidArgumentException` keeps generic catch blocks
 * and existing test expectations working without churn.
 *
 * Factory methods cover each violation shape the package currently raises so
 * the message format stays consistent across drivers — call sites pass a
 * short natural-language context string (e.g. `'OTP code length'`,
 * `'Backup-code alphabet'`) and the factory assembles the rest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class InvalidDriverConfigurationException extends \InvalidArgumentException
{
    /**
     * Raised when a configured code length is less than 1 — the numeric OTP
     * path would mint a one-character `"0"` code and the alphabet path would
     * return an empty string.
     *
     * @param  string  $context
     * @param  int  $got
     * @return self
     */
    public static function codeLengthTooSmall(string $context, int $got): self
    {
        return new self(sprintf('%s must be at least 1; got [%d].', $context, $got));
    }

    /**
     * Raised when a configured expiry is less than 1 minute — any issued code
     * would be "expired" on arrival.
     *
     * @param  string  $context
     * @param  int  $got
     * @return self
     */
    public static function expiryTooSmall(string $context, int $got): self
    {
        return new self(sprintf('%s must be at least 1 minute; got [%d].', $context, $got));
    }

    /**
     * Raised when a configured `maxAttempts` is negative — the manager's
     * `>=` lockout threshold would never match and the lockout would silently
     * never apply.
     *
     * @param  string  $context
     * @param  int  $got
     * @return self
     */
    public static function negativeMaxAttempts(string $context, int $got): self
    {
        return new self(sprintf('%s must be zero or greater; got [%d].', $context, $got));
    }

    /**
     * Raised when a configured alphabet has fewer than two characters — a
     * single-character alphabet mints zero-entropy codes, an empty alphabet
     * explodes inside `random_int(0, -1)`.
     *
     * @param  string  $context
     * @param  string  $alphabet
     * @return self
     */
    public static function alphabetTooShort(string $context, string $alphabet): self
    {
        $detail = $alphabet === '' ? 'an empty string' : 'a single character';

        return new self(sprintf('%s must contain at least two characters; received %s.', $context, $detail));
    }

    /**
     * Raised when a rendered-message template does not contain the required
     * placeholder — without it the rendered message would ship the literal
     * template string to users on every challenge.
     *
     * @param  string  $context
     * @param  string  $template
     * @param  string  $placeholder
     * @return self
     */
    public static function templateMissingPlaceholder(string $context, string $template, string $placeholder): self
    {
        return new self(sprintf('%s must contain the %s placeholder; received "%s".', $context, $placeholder, $template));
    }

    /**
     * Raised when a requested batch count is less than 1 — the driver cannot
     * mint a sensible zero- or negative-sized batch.
     *
     * @param  string  $context
     * @param  int  $got
     * @return self
     */
    public static function batchCountTooSmall(string $context, int $got): self
    {
        return new self(sprintf('%s must be at least 1; got [%d].', $context, $got));
    }

    /**
     * Raised when a requested batch size exceeds the configured code space —
     * the driver cannot mint that many distinct codes without dipping into
     * duplicates, so callers are asked to widen the alphabet or increase the
     * code length.
     *
     * @param  string  $context
     * @param  int  $alphabetLength
     * @param  int  $codeLength
     * @param  int  $capacity
     * @param  int  $count
     * @return self
     */
    public static function codeSpaceSmallerThanBatch(string $context, int $alphabetLength, int $codeLength, int $capacity, int $count): self
    {
        $detail = sprintf('alphabet=%d, length=%d, capacity=%d', $alphabetLength, $codeLength, $capacity);

        return new self(sprintf('%s (%s) is smaller than the batch size %d.', $context, $detail, $count));
    }
}
