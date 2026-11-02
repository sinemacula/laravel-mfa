<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Contracts;

use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;

/**
 * Provisioning driver contract.
 *
 * A factor driver whose enrolment secret is shown to the person as a URI an
 * authenticator app reads from a QR code. Starting an enrolment of such a type
 * needs the account name the app shows, and returns the URI with the secret,
 * once.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ProvisioningDriver extends FactorDriver
{
    /**
     * The provisioning URI of the factor and its secret, itself a secret, since
     * it holds the secret.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $issuer
     * @param  string  $accountName
     * @param  \SineMacula\Laravel\Mfa\Secrets\RevealedSecret  $secret
     * @return \SineMacula\Laravel\Mfa\Secrets\RevealedSecret
     *
     * @throws \InvalidArgumentException
     */
    public function provisioningUri(Factor $factor, string $issuer, string $accountName, #[\SensitiveParameter] RevealedSecret $secret): RevealedSecret;
}
