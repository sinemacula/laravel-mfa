<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use SineMacula\Laravel\Mfa\Factors\FactorLabel;

/**
 * What a person asks to enrol. The destination is hidden from dumps until the
 * driver normalises it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentRequest
{
    /** @var \SensitiveParameterValue */
    private \SensitiveParameterValue $destination;

    /**
     * @param  string  $type
     * @param  ?string  $label
     * @param  ?string  $destination
     * @param  ?string  $accountName
     * @param  ?string  $issuer
     */
    private function __construct(

        /** Factor type. */
        public string $type,

        /** Trimmed; blank is null. */
        public ?string $label,

        // For a delivered type.
        #[\SensitiveParameter]
        ?string $destination = null,

        /** Account name an authenticator app shows. */
        public ?string $accountName = null,

        /** Overrides the configured issuer. */
        public ?string $issuer = null,
    ) {
        $this->destination = new \SensitiveParameterValue($destination);
    }

    /**
     * @param  string  $accountName
     * @param  ?string  $label
     * @param  ?string  $issuer
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function totp(string $accountName, ?string $label = null, ?string $issuer = null): self
    {
        return self::provisioned('totp', $accountName, $label, $issuer);
    }

    /**
     * A type whose driver implements `Contracts\ProvisioningDriver`.
     *
     * @param  string  $type
     * @param  string  $accountName
     * @param  ?string  $label
     * @param  ?string  $issuer
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function provisioned(string $type, string $accountName, ?string $label = null, ?string $issuer = null): self
    {
        return new self($type, FactorLabel::normalize($label), null, $accountName, $issuer);
    }

    /**
     * @param  string  $type
     * @param  string  $destination
     * @param  ?string  $label
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function delivered(string $type, #[\SensitiveParameter] string $destination, ?string $label = null): self
    {
        return new self($type, FactorLabel::normalize($label), $destination);
    }

    /**
     * @param  string  $type
     * @param  ?string  $label
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(string $type, ?string $label = null): self
    {
        return new self($type, FactorLabel::normalize($label));
    }

    /**
     * Not yet normalised.
     *
     * @return ?string
     */
    public function destination(): ?string
    {
        /** @var ?string */
        return $this->destination->getValue();
    }
}
