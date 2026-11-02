<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;

/**
 * The `Reauthenticator` contract kit: it answers nothing, or a reauthentication
 * with the first factor it has just made for the identity on the application.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `ReauthenticatorContract`.
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
     * The answer is nothing, or a fresh reauthentication of the identity on the
     * application.
     *
     * @return void
     */
    public function testReauthenticatorNeverAnswersAProofItDidNotJustMake(): void
    {
        ReauthenticatorContract::assertNeverAnswersAProofItDidNotJustMake($this->reauthenticator(), $this->reauthenticatingIdentity(), $this->reauthenticationApplication());
    }

    /**
     * The reauthenticator under test.
     *
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
     * The application asked about.
     *
     * @return string
     */
    abstract protected function reauthenticationApplication(): string;
}
