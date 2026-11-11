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
 * A type of the application's own, provisioned as TOTP is, with a fixed secret
 * and one accepted code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HardwareAppDriver implements ProvisioningDriver
{
    /** @var string */
    public const string TYPE = 'hardware_app';

    /** @var string */
    public const string SECRET = 'hardware-secret';

    /** @var string */
    public const string CODE = '246810';

    /**
     * @return \SineMacula\Laravel\Mfa\Enums\ChannelKind
     */
    #[\Override]
    public function channelKind(): ChannelKind
    {
        return ChannelKind::AUTHENTICATOR_APP;
    }

    /**
     * @return list<string>
     */
    #[\Override]
    public function amr(): array
    {
        return [];
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     */
    #[\Override]
    public function startEnrollment(Factor $factor): RevealedSecret
    {
        return new RevealedSecret(self::SECRET);
    }

    /**
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
