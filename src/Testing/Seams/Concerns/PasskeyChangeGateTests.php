<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\PasskeyChangeGateContract;

/**
 * The passkey change gate wiring kit: a registration path calls the gate inside
 * its own change, so a registration the gate refuses keeps nothing; and its
 * calls into the gate refuse a call outside a transaction.
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
        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->gatedIdentity(), $this->registerPasskey(...), $this->isPasskeyStored(...));
    }

    /**
     * The path's calls into the gate refuse a call outside a transaction.
     *
     * @return void
     */
    public function testPasskeyChangeGateNeedsTheCallersTransaction(): void
    {
        $identity    = $this->gatedIdentity();
        $application = $this->gatedApplication();

        PasskeyChangeGateContract::assertTheGateNeedsTheCallersTransaction(
            fn (#[\SensitiveParameter] string $credentialId): mixed => $this->gateRegistering($identity, $application, $credentialId),
            fn (#[\SensitiveParameter] string $credentialId): mixed => $this->gateRemoving($identity, $application, $credentialId),
        );
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
    abstract protected function registerPasskey(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): mixed;

    /**
     * Whether the path kept the credential.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return bool
     */
    abstract protected function isPasskeyStored(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): bool;

    /**
     * Call the gate's `registering()` through the adapter under test, for the
     * identity on the application, with the credential id.
     *
     * Call the adapter's own call into the gate, not the registration path
     * around it, which may rightly open a transaction: never inside a
     * transaction of the hook's own, and letting every exception through.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     */
    abstract protected function gateRegistering(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed;

    /**
     * Call the gate's `removing()` through the adapter under test, for the
     * identity on the application, with the credential id.
     *
     * Call the adapter's own call into the gate, not the removal path around
     * it, which may rightly open a transaction: never inside a transaction of
     * the hook's own, and letting every exception through.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     */
    abstract protected function gateRemoving(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed;
}
