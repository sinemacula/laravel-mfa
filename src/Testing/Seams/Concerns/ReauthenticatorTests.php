<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Testing\Seams\ReauthenticatorContract;

/**
 * The `Reauthenticator` contract kit; each check delegates to
 * `ReauthenticatorContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait ReauthenticatorTests
{
    /**
     * @return void
     */
    public function testReauthenticatorNeverAnswersAProofItDidNotJustMake(): void
    {
        ReauthenticatorContract::assertNeverAnswersAProofItDidNotJustMake($this->reauthenticator(), $this->reauthenticatingIdentity(), $this->reauthenticationApplication());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\Reauthenticator
     */
    abstract protected function reauthenticator(): Reauthenticator;

    /**
     * An identity signed in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function reauthenticatingIdentity(): MultiFactorAuthenticatable;

    /**
     * @return string
     */
    abstract protected function reauthenticationApplication(): string;
}
