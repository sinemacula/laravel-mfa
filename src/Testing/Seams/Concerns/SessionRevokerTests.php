<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionRevokerContract;

/**
 * The `SessionRevoker` contract kit; each check delegates to
 * `SessionRevokerContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait SessionRevokerTests
{
    /**
     * @return void
     */
    public function testSessionRevokerStopsAnotherSessionCountingWhenAFactorIsRemoved(): void
    {
        $identity = $this->revokedIdentity();

        SessionRevokerContract::assertRemovingAFactorStopsAnotherSessionCounting(
            $this->sessionRevoker(),
            $identity,
            $this->removedFactorId($identity),
            $this->revokedApplication(),
            $this->currentSessionOf($identity),
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
        );
    }

    /**
     * @return void
     */
    public function testSessionRevokerSparesNothingWhenAFactorIsRemovedFromAnotherSignIn(): void
    {
        $identity = $this->revokedIdentity();

        $this->currentSessionOf($identity);

        SessionRevokerContract::assertRemovingAFactorFromAnotherSignInSparesNothing(
            $this->sessionRevoker(),
            $identity,
            $this->removedFactorId($identity),
            $this->revokedApplication(),
            'another-sign-in',
            $this->doesCurrentSessionCount(...),
        );
    }

    /**
     * @return void
     */
    public function testSessionRevokerStopsAnotherSessionCountingWhenRevokingAll(): void
    {
        SessionRevokerContract::assertRevokingAllStopsAnotherSessionCounting(
            $this->sessionRevoker(),
            $this->revokedIdentity(),
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
        );
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionRevokerLeavesSessionsCountingWhenRolledBack(): void
    {
        $identity = $this->revokedIdentity();

        SessionRevokerContract::assertARolledBackRevocationLeavesSessionsCounting(
            $this->sessionRevoker(),
            $identity,
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
            $this->removedFactorId($identity),
            $this->revokedApplication(),
            $this->currentSessionOf($identity),
        );
    }

    /**
     * @return string
     */
    abstract protected function revokedApplication(): string;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\SessionRevoker
     */
    abstract protected function sessionRevoker(): SessionRevoker;

    /**
     * An identity with a current session.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function revokedIdentity(): MultiFactorAuthenticatable;

    /**
     * The id of a factor of the identity that is being removed.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    abstract protected function removedFactorId(MultiFactorAuthenticatable $identity): string;

    /**
     * The current sign-in's session id, verified so that it counts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    abstract protected function currentSessionOf(MultiFactorAuthenticatable $identity): string;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    abstract protected function doesCurrentSessionCount(MultiFactorAuthenticatable $identity): bool;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    abstract protected function verifyAnotherSession(MultiFactorAuthenticatable $identity): void;

    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    abstract protected function doesAnotherSessionCount(MultiFactorAuthenticatable $identity): bool;
}
