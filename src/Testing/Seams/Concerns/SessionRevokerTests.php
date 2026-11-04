<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Testing\Seams\SessionRevokerContract;

/**
 * The `SessionRevoker` contract kit: a factor's removal, or revoking every
 * session, stops another session counting; a factor's removal from another
 * sign-in never spares the current session; and a revocation that rolls back
 * leaves another session counting.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `SessionRevokerContract`.
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
     * A factor's removal stops another session counting.
     *
     * @return void
     */
    public function testSessionRevokerStopsAnotherSessionCountingWhenAFactorIsRemoved(): void
    {
        $identity = $this->revokedIdentity();

        SessionRevokerContract::assertRemovingAFactorStopsAnotherSessionCounting(
            $this->sessionRevoker(),
            $identity,
            $this->removedFactorId($identity),
            $this->currentSessionOf($identity),
            $this->verifyAnotherSession(...),
            $this->doesAnotherSessionCount(...),
        );
    }

    /**
     * A factor's removal from another sign-in never spares the current session.
     *
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
            'another-sign-in',
            $this->doesCurrentSessionCount(...),
        );
    }

    /**
     * Revoking every session stops another session counting.
     *
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
     * A revocation that rolls back leaves another session counting.
     *
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
            $this->currentSessionOf($identity),
        );
    }

    /**
     * The revoker under test.
     *
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
     * The session id of the identity's current sign-in, its proofs verified so
     * that it counts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    abstract protected function currentSessionOf(MultiFactorAuthenticatable $identity): string;

    /**
     * Whether the identity's current session still counts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    abstract protected function doesCurrentSessionCount(MultiFactorAuthenticatable $identity): bool;

    /**
     * Verify another session of the identity, so that it counts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    abstract protected function verifyAnotherSession(MultiFactorAuthenticatable $identity): void;

    /**
     * Whether the other session verified still counts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return bool
     */
    abstract protected function doesAnotherSessionCount(MultiFactorAuthenticatable $identity): bool;
}
