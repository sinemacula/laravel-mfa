<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Testing\Seams\PasskeyGatewayContract;

/**
 * The `PasskeyGateway` contract kit; each check delegates to
 * `PasskeyGatewayContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait PasskeyGatewayTests
{
    /**
     * @return void
     */
    public function testPasskeyGatewayListsNothingWhenUnavailable(): void
    {
        PasskeyGatewayContract::assertAnUnavailableGatewayListsNothing($this->passkeyGateway(), $this->passkeyIdentity(), $this->passkeyBinding()->application);
    }

    /**
     * @return void
     */
    public function testPasskeyGatewayVerifiesNothingWithoutAnAllowedCredential(): void
    {
        PasskeyGatewayContract::assertNothingVerifiesWithoutAnAllowedCredential($this->passkeyGateway(), $this->passkeyIdentity(), $this->passkeyBinding(), ['id' => 'contract']);
    }

    /**
     * @return void
     */
    public function testPasskeyGatewayNeverVerifiesAnEmptyResponse(): void
    {
        PasskeyGatewayContract::assertAnEmptyResponseNeverVerifies($this->passkeyGateway(), $this->passkeyIdentity(), $this->passkeyBinding());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PasskeyGateway
     */
    abstract protected function passkeyGateway(): PasskeyGateway;

    /**
     * An identity the gateway knows.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function passkeyIdentity(): MultiFactorAuthenticatable;

    /**
     * @return \SineMacula\Laravel\Mfa\Proofs\ProofBinding
     */
    abstract protected function passkeyBinding(): ProofBinding;
}
