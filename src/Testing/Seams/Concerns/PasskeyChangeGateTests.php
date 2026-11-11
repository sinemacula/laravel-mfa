<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\PasskeyChangeGateContract;

/**
 * The passkey change gate wiring kit for a registration path; each check
 * delegates to `PasskeyChangeGateContract`.
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
     * @return void
     */
    public function testPasskeyChangeGateRollsBackARefusedRegistration(): void
    {
        PasskeyChangeGateContract::assertARefusedGateRollsBackTheRegistration($this->gatedIdentity(), $this->registerPasskey(...), $this->isPasskeyStored(...));
    }

    /**
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
     * @return string
     */
    abstract protected function gatedApplication(): string;

    /**
     * Register through the path under test, which calls the gate inside its own
     * transaction.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return mixed
     */
    abstract protected function registerPasskey(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): mixed;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return bool
     */
    abstract protected function isPasskeyStored(MultiFactorAuthenticatable $identity, #[\SensitiveParameter] string $credentialId): bool;

    /**
     * Make the adapter's own `registering()` call, not the path around it,
     * which may open a transaction; open none here and let every exception
     * through.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     */
    abstract protected function gateRegistering(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed;

    /**
     * As `gateRegistering()`, for the adapter's own `removing()` call.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @return mixed
     */
    abstract protected function gateRemoving(MultiFactorAuthenticatable $identity, string $application, #[\SensitiveParameter] string $credentialId): mixed;
}
