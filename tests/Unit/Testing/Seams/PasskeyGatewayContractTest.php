<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\OperationRefusedException;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertion;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PasskeyGatewayTests;
use SineMacula\Laravel\Mfa\Testing\Seams\PasskeyGatewayContract;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Passkeys\FakePasskeyGateway;
use Tests\TestCase;

/**
 * The `PasskeyGateway` contract kit proves the unavailable default and a
 * gateway that verifies only against its allowlist, and rejects one that lists
 * passkeys while unavailable or verifies an empty response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyGatewayContract::class)]
#[CoversClass(UnavailablePasskeyGateway::class)]
final class PasskeyGatewayContractTest extends TestCase
{
    use PasskeyGatewayTests;

    /**
     * The default is unavailable, lists nothing, refuses to verify counting
     * nothing, and refuses to start a ceremony.
     *
     * @return void
     */
    public function testTheDefaultIsUnavailable(): void
    {
        $gateway = new UnavailablePasskeyGateway;

        self::assertFalse($gateway->isAvailable());
        self::assertSame([], $gateway->credentialIds($this->passkeyIdentity()));

        try {
            $gateway->verifyAssertion($this->passkeyIdentity(), $this->passkeyBinding(), ['Y3JlZGVudGlhbC1vbmU'], ['id' => 'x']);

            self::fail('The default must refuse to verify.');
        } catch (OperationRefusedException $exception) {
            self::assertSame(FailureReason::TYPE_NOT_ENABLED, $exception->reason);
        }

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Passkeys are unavailable: bind a passkey gateway to ' . PasskeyGateway::class . '.');

        $gateway->requestAssertion($this->passkeyIdentity(), $this->passkeyBinding(), ['Y3JlZGVudGlhbC1vbmU']);
    }

    /**
     * An available gateway that verifies only a non-empty response against a
     * non-empty allowlist passes the kit.
     *
     * @return void
     */
    public function testAcceptsAGatewayThatVerifiesOnlyItsAllowlist(): void
    {
        $gateway = self::verifying(true);

        PasskeyGatewayContract::assertAnUnavailableGatewayListsNothing($gateway, $this->passkeyIdentity());
        PasskeyGatewayContract::assertNothingVerifiesWithoutAnAllowedCredential($gateway, $this->passkeyIdentity(), $this->passkeyBinding(), ['id' => 'x']);
        PasskeyGatewayContract::assertAnEmptyResponseNeverVerifies($gateway, $this->passkeyIdentity(), $this->passkeyBinding());
    }

    /**
     * A gateway that refuses to verify at all passes the kit, as the default
     * does, and so does one that says why it did not.
     *
     * @return void
     */
    public function testAcceptsAGatewayThatRefusesOrSaysWhy(): void
    {
        $gateway = new FakePasskeyGateway(['Y3JlZGVudGlhbC1vbmU'], refusal: new OperationRefusedException(FailureReason::TYPE_NOT_ENABLED, 'Unavailable.'));

        PasskeyGatewayContract::assertNothingVerifiesWithoutAnAllowedCredential($gateway, $this->passkeyIdentity(), $this->passkeyBinding(), ['id' => 'x']);
        PasskeyGatewayContract::assertAnEmptyResponseNeverVerifies(new FakePasskeyGateway(['Y3JlZGVudGlhbC1vbmU']), $this->passkeyIdentity(), $this->passkeyBinding());
    }

    /**
     * The kit rejects an unavailable gateway that lists passkeys.
     *
     * @return void
     */
    public function testRejectsAnUnavailableGatewayThatListsPasskeys(): void
    {
        $this->expectException(AssertionFailedError::class);

        PasskeyGatewayContract::assertAnUnavailableGatewayListsNothing(self::verifying(false), $this->passkeyIdentity());
    }

    /**
     * The kit rejects a gateway that verifies against an empty allowlist.
     *
     * @return void
     */
    public function testRejectsAGatewayThatVerifiesWithoutAnAllowlist(): void
    {
        $gateway = new FakePasskeyGateway([], new PasskeyAssertion('Y3JlZGVudGlhbC1vbmU', new ObservedProperties(userPresence: true)), checksAllowlist: false);

        $this->expectException(AssertionFailedError::class);

        PasskeyGatewayContract::assertNothingVerifiesWithoutAnAllowedCredential($gateway, $this->passkeyIdentity(), $this->passkeyBinding(), ['id' => 'x']);
    }

    /**
     * The kit rejects a gateway that verifies an empty response.
     *
     * @return void
     */
    public function testRejectsAGatewayThatVerifiesAnEmptyResponse(): void
    {
        $gateway = new FakePasskeyGateway(['Y3JlZGVudGlhbC1vbmU'], new PasskeyAssertion('Y3JlZGVudGlhbC1vbmU', new ObservedProperties(userPresence: true)), checksResponse: false);

        $this->expectException(AssertionFailedError::class);

        PasskeyGatewayContract::assertAnEmptyResponseNeverVerifies($gateway, $this->passkeyIdentity(), $this->passkeyBinding());
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway
     */
    #[\Override]
    protected function passkeyGateway(): PasskeyGateway
    {
        return $this->container()->make(PasskeyGateway::class);
    }

    /**
     * A person.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function passkeyIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * A step-up binding.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    #[\Override]
    protected function passkeyBinding(): ProofBinding
    {
        return new ProofBinding(NonEloquentIdentity::class, 'plain-1', 'web', 'sign-in-1', Purpose::STEP_UP);
    }

    /**
     * A fake gateway listing one passkey and verifying it.
     *
     * @param  bool  $available
     * @return \Tests\Fixtures\Passkeys\FakePasskeyGateway
     */
    private static function verifying(bool $available): FakePasskeyGateway
    {
        return new FakePasskeyGateway(['Y3JlZGVudGlhbC1vbmU'], new PasskeyAssertion('Y3JlZGVudGlhbC1vbmU', new ObservedProperties(userPresence: true)), $available);
    }
}
