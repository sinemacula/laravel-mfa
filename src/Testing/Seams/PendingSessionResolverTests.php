<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * The `PendingSessionResolver` contract kit: a request with no pending
 * credential has no pending session, and one whose credential does not validate
 * is refused by throwing.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `PendingSessionResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait PendingSessionResolverTests
{
    /**
     * A request with no pending credential has no pending session.
     *
     * @return void
     */
    public function testPendingSessionResolverFindsNoneWithoutACredential(): void
    {
        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession($this->pendingSessionResolver(), $this->requestWithoutPendingCredential());
    }

    /**
     * A request whose pending credential does not validate is refused by
     * throwing.
     *
     * @return void
     */
    public function testPendingSessionResolverRefusesAnInvalidCredential(): void
    {
        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused($this->pendingSessionResolver(), $this->requestWithInvalidPendingCredential());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver
     */
    abstract protected function pendingSessionResolver(): PendingSessionResolver;

    /**
     * A request that carries no pending credential.
     *
     * @return \Illuminate\Http\Request
     */
    abstract protected function requestWithoutPendingCredential(): Request;

    /**
     * A request carrying a pending credential that does not validate, or `null`
     * for a resolver with no pending credentials at all.
     *
     * @return ?\Illuminate\Http\Request
     */
    abstract protected function requestWithInvalidPendingCredential(): ?Request;
}
