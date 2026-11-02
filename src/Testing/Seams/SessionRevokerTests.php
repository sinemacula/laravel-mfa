<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;

/**
 * The `SessionRevoker` contract kit: revoking the other sessions, or all of
 * them, stops another session counting, and a revocation that rolls back leaves
 * it counting.
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
     * Revoking the other sessions stops another session counting.
     *
     * @return void
     */
    public function testSessionRevokerStopsAnotherSessionCountingWhenRevokingOthers(): void
    {
        SessionRevokerContract::assertRevokingOthersStopsAnotherSessionCounting($this->sessionRevoker(), $this->revokedIdentity(), $this->verifyAnotherSession(...), $this->anotherSessionCounts(...));
    }

    /**
     * Revoking every session stops another session counting.
     *
     * @return void
     */
    public function testSessionRevokerStopsAnotherSessionCountingWhenRevokingAll(): void
    {
        SessionRevokerContract::assertRevokingAllStopsAnotherSessionCounting($this->sessionRevoker(), $this->revokedIdentity(), $this->verifyAnotherSession(...), $this->anotherSessionCounts(...));
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
        SessionRevokerContract::assertARolledBackRevocationLeavesSessionsCounting($this->sessionRevoker(), $this->revokedIdentity(), $this->verifyAnotherSession(...), $this->anotherSessionCounts(...));
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
    abstract protected function anotherSessionCounts(MultiFactorAuthenticatable $identity): bool;
}
