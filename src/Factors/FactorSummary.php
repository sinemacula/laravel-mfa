<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * Public-safe projection of a `Factor` for events, exception payloads and the
 * list of factors a person chooses from.
 *
 * Carries only what an application needs to show a factor: its id, type, label,
 * a masked destination, its status, whether it is preferred and when it was
 * last used. Never the factor model, its secret, a code, its credential
 * reference or the full destination, so it is safe in a queued listener's
 * payload and in a log.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorSummary implements \JsonSerializable
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $type
     * @param  ?string  $label
     * @param  ?string  $maskedDestination
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorStatus  $status
     * @param  bool  $preferred
     * @param  ?\Carbon\CarbonInterface  $lastUsedAt
     */
    public function __construct(

        /** Factor identifier (a ULID on the shipped model). */
        public string $id,

        /** The factor's type (`totp`, `email`, `sms`, `passkey` or an application's own). */
        public string $type,

        /** The label the person chose, if any. */
        public ?string $label,

        /** The destination of an SMS or email factor, masked; null otherwise. */
        public ?string $maskedDestination,

        /** Where the factor is in its enrolment. */
        public FactorStatus $status,

        /** Whether the factor is the identity's preferred one. */
        public bool $preferred,

        /** When the factor was last used to verify. */
        public ?CarbonInterface $lastUsedAt,
    ) {}

    /**
     * Build a summary from a factor, masking its destination.
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
            type: $factor->getType(),
            label: $factor->getLabel(),
            maskedDestination: self::mask($factor->getDestination()),
            status: $factor->getStatus(),
            preferred: $factor->isPreferred(),
            lastUsedAt: $factor->getLastUsedAt(),
        );
    }

    /**
     * Render the summary as a plain associative array for JSON serialisation,
     * with `last_used_at` as ISO 8601 (or `null`).
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return [
            'id'                 => $this->id,
            'type'               => $this->type,
            'label'              => $this->label,
            'masked_destination' => $this->maskedDestination,
            'status'             => $this->status->value,
            'preferred'          => $this->preferred,
            'last_used_at'       => $this->lastUsedAt?->toIso8601String(),
        ];
    }

    /**
     * Mask a delivery destination for safe public surfacing.
     *
     * Emails: keep the domain, mask the local-part except its leading two
     * characters (or one if the local-part is a single character). Phone
     * numbers and any other opaque shape: keep the last four characters, mask
     * the rest; inputs of four characters or fewer are fully masked.
     *
     * @param  ?string  $destination
     * @return ?string
     */
    private static function mask(#[\SensitiveParameter] ?string $destination): ?string
    {
        if ($destination === null || $destination === '') {
            return $destination;
        }

        return str_contains($destination, '@')
            ? self::maskEmail($destination)
            : self::maskOpaque($destination);
    }

    /**
     * Mask an email address: keep the domain intact, mask the local-part except
     * for the leading two characters (or one if the local-part is a single
     * character).
     *
     * @param  string  $destination
     * @return string
     */
    private static function maskEmail(#[\SensitiveParameter] string $destination): string
    {
        [$local, $domain] = explode('@', $destination, 2);

        $keep   = min(2, (int) max(1, floor(strlen($local) / 2)));
        $prefix = substr($local, 0, $keep);
        $masked = $prefix . str_repeat('*', max(1, strlen($local) - $keep));

        return $masked . '@' . $domain;
    }

    /**
     * Mask a phone number / opaque destination: keep the last four characters,
     * mask everything before them. If the input is four or fewer characters,
     * mask all of it.
     *
     * @param  string  $destination
     * @return string
     */
    private static function maskOpaque(#[\SensitiveParameter] string $destination): string
    {
        $keep   = 4;
        $length = strlen($destination);

        return $length <= $keep
            ? str_repeat('*', $length)
            : str_repeat('*', $length - $keep) . substr($destination, -$keep);
    }
}
