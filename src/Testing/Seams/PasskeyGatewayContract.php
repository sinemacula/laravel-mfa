<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;

/**
 * What every `PasskeyGateway` must guarantee: an unavailable gateway lists no
 * passkeys, and neither an empty allowlist nor an empty response verifies.
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public static function assertAnUnavailableGatewayListsNothing(PasskeyGateway $gateway, MultiFactorAuthenticatable $identity): void
    {
        Assert::assertTrue($gateway->isAvailable() || $gateway->credentialIds($identity) === [], 'An unavailable gateway must list no passkeys.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @param  array<string, mixed>  $response
     * @return void
     */
    public static function assertNothingVerifiesWithoutAnAllowedCredential(
        PasskeyGateway $gateway,
        MultiFactorAuthenticatable $identity,
        ProofBinding $binding,
        array $response,
    ): void {
        self::assertDoesNotVerify(static fn () => $gateway->verifyAssertion($identity, $binding, [], $response), 'An assertion must never verify against an empty allowlist.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway  $gateway
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofBinding  $binding
     * @return void
     */
    public static function assertAnEmptyResponseNeverVerifies(PasskeyGateway $gateway, MultiFactorAuthenticatable $identity, ProofBinding $binding): void
    {
        self::assertDoesNotVerify(static fn () => $gateway->verifyAssertion($identity, $binding, $gateway->credentialIds($identity), []), 'An empty response must never verify.');
    }

    /**
     * A reason or an `OperationRefusedException`, never an assertion.
     *
     * @param  \Closure(): (\SineMacula\Laravel\Mfa\Enums\FailureReason|\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion)  $verification
     * @param  string  $message
     * @return void
     */
    private static function assertDoesNotVerify(\Closure $verification, string $message): void
    {
        try {
            Assert::assertInstanceOf(FailureReason::class, $verification(), $message);
        } catch (OperationRefusedException) {
            return;
        }
    }
}
