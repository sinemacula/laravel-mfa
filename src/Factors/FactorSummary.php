<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Enums\FactorStatus;

/**
 * A projection of a `Factor` safe for events, logs and responses: never the
 * model, its secret, a code, its credential reference or full destination.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorSummary implements \JsonSerializable
{
    /**
     * @param  string  $id
     * @param  string  $type
     * @param  ?string  $label
     * @param  ?string  $maskedDestination
     * @param  \SineMacula\Laravel\Mfa\Enums\FactorStatus  $status
     * @param  bool  $preferred
     * @param  ?\Carbon\CarbonInterface  $lastUsedAt
     * @param  bool  $disabled
     */
    public function __construct(

        /** A ULID on the shipped model. */
        public string $id,

        /** `totp`, `email`, `sms`, `passkey` or an application's own. */
        public string $type,

        /** Chosen by the person. */
        public ?string $label,

        /** An SMS or email factor's destination, masked. */
        public ?string $maskedDestination,

        /** Enrolment status. */
        public FactorStatus $status,

        /** Whether it is the identity's preferred factor. */
        public bool $preferred,

        /** Last successful verification. */
        public ?CarbonInterface $lastUsedAt,

        /** Disabled by the failure ceiling. Not disabled does not mean offered. */
        public bool $disabled = false,
    ) {}

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return self
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\InvalidModelException
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
            disabled: $factor->getDisabledAt() !== null,
        );
    }

    /**
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
            'disabled'           => $this->disabled,
        ];
    }

    /**
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
     * Keeps the domain and up to two leading characters of the local part.
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
     * Keeps the last four characters, or none of a destination that short.
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
