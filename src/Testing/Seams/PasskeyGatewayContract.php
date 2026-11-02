<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * What every `PasskeyGateway` must guarantee, as assertions: an unavailable
 * gateway lists no passkeys, no assertion verifies against an empty
 * allowlist, and an empty response never verifies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class PasskeyGatewayContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A gateway that is not available lists no passkeys to offer.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public static function assertAnUnavailableGatewayListsNothing(PasskeyGateway $gateway, MultiFactorAuthenticatable $identity): void
    {
        Assert::assertTrue($gateway->isAvailable() || $gateway->credentialIds($identity) === [], 'An unavailable gateway must list no passkeys.');
    }

    /**
     * Nothing verifies against an empty allowlist.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  array<string, mixed>  $response
     * @return void
     */
    public static function assertNothingVerifiesWithoutAnAllowedCredential(PasskeyGateway $gateway, MultiFactorAuthenticatable $identity, ProofBinding $binding, array $response): void
    {
        Assert::assertNull($gateway->verifyAssertion($identity, $binding, [], $response), 'An assertion must never verify against an empty allowlist.');
    }

    /**
     * An empty response verifies for none of the identity's passkeys.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     */
    public static function assertAnEmptyResponseNeverVerifies(PasskeyGateway $gateway, MultiFactorAuthenticatable $identity, ProofBinding $binding): void
    {
        Assert::assertNull($gateway->verifyAssertion($identity, $binding, $gateway->credentialIds($identity), []), 'An empty response must never verify.');
    }
}
