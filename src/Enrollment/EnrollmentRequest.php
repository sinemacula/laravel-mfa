<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enrollment;

use SineMacula\Laravel\Mfa\Factors\FactorLabel;

/**
 * What a person asks to enrol: an authenticator app, or an application's own
 * type provisioned the same way, under an account name; a delivered type with
 * its destination; or any other type; with the label they chose. The
 * destination is hidden from dumps, as it stays until the driver has normalised
 * it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EnrollmentRequest
{
    /** @var \SensitiveParameterValue The destination given, hidden from dumps. */
    private \SensitiveParameterValue $destination;

    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  ?string  $label
     * @param  ?string  $destination
     * @param  ?string  $accountName
     * @param  ?string  $issuer
     */
    private function __construct(

        /** The type to enrol. */
        public string $type,

        /** The label the person chose, trimmed, with a blank one as none. */
        public ?string $label,

        // The destination given, for a delivered type.
        #[\SensitiveParameter]
        ?string $destination = null,

        /** The account name an authenticator app shows, for a type that provisions one. */
        public ?string $accountName = null,

        /** The issuer an authenticator app shows, in place of the configured one. */
        public ?string $issuer = null,
    ) {
        $this->destination = new \SensitiveParameterValue($destination);
    }

    /**
     * An authenticator app, under the account name and issuer it shows.
     *
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
     * A type whose driver provisions an authenticator app (see
     * `Contracts\ProvisioningDriver`), under the account name and issuer it
     * shows.
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
     * A delivered type, with the destination its first code goes to.
     *
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
     * Any other type.
     *
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
     * The destination given, as given.
     *
     * @return ?string
     */
    public function destination(): ?string
    {
        /** @var ?string */
        return $this->destination->getValue();
    }
}
