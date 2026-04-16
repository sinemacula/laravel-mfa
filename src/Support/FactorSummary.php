<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Support;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Contracts\Factor;

/**
 * Public-safe projection of a `Factor` for exception payloads and UI
 * disambiguation.
 *
 * Carries only the fields a consuming application needs to render a
 * factor-picker UI (id, driver, label, verified-at, a masked delivery
 * destination). Never leaks `secret`, `code`, `attempts`, or the raw
 * recipient — consumers that need those fields read from the Factor
 * record directly.
 *
 * Immutable, JSON-serialisable, safe to ship through exception payloads
 * and log sinks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class FactorSummary implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $driver
     * @param  ?string  $label
     * @param  ?string  $maskedRecipient
     * @param  ?\Carbon\CarbonInterface  $verifiedAt
     */
    public function __construct(

        /** Factor identifier (ULID on the shipped model). */
        public string $id,

        /** Registered driver name (e.g. `'totp'`, `'email'`, `'sms'`). */
        public string $driver,

        /** Optional human-readable label. */
        public ?string $label,

        /** Masked delivery destination for OTP drivers; null otherwise. */
        public ?string $maskedRecipient,

        /** When the factor was last successfully verified. */
        public ?CarbonInterface $verifiedAt,

    ) {}

    /**
     * Build a summary from a concrete `Factor` instance, masking the
     * recipient to defence-in-depth against log leakage.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return self
     */
    public static function fromFactor(Factor $factor): self
    {
        $identifier = $factor->getFactorIdentifier();

        $id = is_string($identifier) || is_int($identifier)
            ? (string) $identifier
            : '';

        return new self(
            id: $id,
            driver: $factor->getDriver(),
            label: $factor->getLabel(),
            maskedRecipient: self::mask($factor->getRecipient()),
            verifiedAt: $factor->getVerifiedAt(),
        );
    }

    /**
     * Render the summary as a plain associative array for JSON
     * serialisation. `verified_at` is emitted as ISO-8601 (or `null`).
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'id'               => $this->id,
            'driver'           => $this->driver,
            'label'            => $this->label,
            'masked_recipient' => $this->maskedRecipient,
            'verified_at'      => $this->verifiedAt?->toIso8601String(),
        ];
    }

    /**
     * Mask a delivery destination for safe public surfacing.
     *
     * Emails: keep the domain, mask the local-part except the last two
     * characters. Phone numbers: keep the last four digits, mask the
     * rest. Any other shape gets its last four characters kept with the
     * rest masked.
     *
     * @param  ?string  $recipient
     * @return ?string
     */
    private static function mask(?string $recipient): ?string
    {
        if ($recipient === null || $recipient === '') {
            return $recipient;
        }

        return str_contains($recipient, '@')
            ? self::maskEmail($recipient)
            : self::maskOpaque($recipient);
    }

    /**
     * Mask an email address: keep the domain intact, mask the local-part
     * except for the leading two characters (or one if the local-part is
     * a single character).
     *
     * @param  string  $recipient
     * @return string
     */
    private static function maskEmail(string $recipient): string
    {
        [$local, $domain] = explode('@', $recipient, 2);

        $keep   = min(2, (int) max(1, floor(strlen($local) / 2)));
        $prefix = substr($local, 0, $keep);
        $masked = $prefix . str_repeat('*', max(1, strlen($local) - $keep));

        return $masked . '@' . $domain;
    }

    /**
     * Mask a phone number / opaque recipient: keep the last four
     * characters, mask everything before them. If the input is four or
     * fewer characters, mask all of it.
     *
     * @param  string  $recipient
     * @return string
     */
    private static function maskOpaque(string $recipient): string
    {
        $keep   = 4;
        $length = strlen($recipient);

        return $length <= $keep
            ? str_repeat('*', $length)
            : str_repeat('*', $length - $keep) . substr($recipient, -$keep);
    }
}
