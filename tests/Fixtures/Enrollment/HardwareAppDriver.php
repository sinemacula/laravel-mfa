<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enrollment;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\ProvisioningDriver;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\CodeCheck;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * An application's own type provisioned as TOTP is, under a type of its own: it
 * starts with a fixed secret and accepts one fixed code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HardwareAppDriver implements ProvisioningDriver
{
    /** @var string The type this driver is registered under. */
    public const string TYPE = 'hardware_app';

    /** @var string The secret every enrolment starts with. */
    public const string SECRET = 'hardware-secret';

    /** @var string The one code it accepts. */
    public const string CODE = '246810';

    /**
     * The channel of an authenticator app.
     *
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * No `amr` values of its own.
     *
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return [];
    }

    /**
     * Start with the fixed secret.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     */
    #[\Override]
    public function startEnrollment(Factor $factor): RevealedSecret
    {
        return new RevealedSecret(self::SECRET);
    }

    /**
     * A URI naming the issuer, the account name and the secret.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $issuer
     * @param  string  $accountName
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $secret
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     */
    #[\Override]
    public function provisioningUri(Factor $factor, string $issuer, string $accountName, #[\SensitiveParameter] RevealedSecret $secret): RevealedSecret
    {
        return new RevealedSecret(sprintf('hardware://%s/%s?secret=%s', $issuer, $accountName, $secret->reveal()));
    }

    /**
     * Confirmed as it is verified.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    #[\Override]
    public function confirm(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        return $this->verify($factor, $code, $binding);
    }

    /**
     * Accept the one code.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return \SineMacula\Laravel\Mfa\Enums\CodeCheck
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code, ProofBinding $binding): CodeCheck
    {
        return hash_equals(self::CODE, $code) ? CodeCheck::ACCEPTED : CodeCheck::INVALID;
    }
}
