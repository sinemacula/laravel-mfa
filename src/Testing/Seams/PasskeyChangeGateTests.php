<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * The passkey change gate wiring kit: a registration path calls the gate inside
 * its own change, so a registration the gate refuses keeps nothing; the gate
 * refuses a call outside a transaction.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `PasskeyChangeGateContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait PasskeyChangeGateTests
{
    /**
     * A registration the gate refuses keeps no credential and associates
     * nothing.
     *
     * @return void
     */
    public function testPasskeyChangeGateRollsBackARefusedRegistration(): void
    {
        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->gatedIdentity(), $this->registerPasskey(...), $this->passkeyIsStored(...));
    }

    /**
     * The gate refuses a call outside a transaction.
     *
     * @return void
     */
    public function testPasskeyChangeGateNeedsTheCallersTransaction(): void
    {
        PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction($this->gatedIdentity(), $this->gatedApplication());
    }

    /**
     * The identity registering passkeys, signed in on an application that
     * enables them.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function gatedIdentity(): MultiFactorAuthenticatable;

    /**
     * The application it registers them on.
     *
     * @return string
     */
    abstract protected function gatedApplication(): string;

    /**
     * Register a passkey with the credential id through the path under test,
     * which calls the gate inside its own change.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return mixed
     */
    abstract protected function registerPasskey(MultiFactorAuthenticatable $identity, string $credentialId): mixed;

    /**
     * Whether the path kept the credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return bool
     */
    abstract protected function passkeyIsStored(MultiFactorAuthenticatable $identity, string $credentialId): bool;
}
