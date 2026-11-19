<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingSessionResolverContract;

/**
 * The `PendingSessionResolver` contract kit; each check delegates to
 * `PendingSessionResolverContract`.
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
     * @return void
     */
    public function testPendingSessionResolverFindsNoneWithoutACredential(): void
    {
        $request = $this->requestWithoutPendingCredential();

        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession($this->pendingSessionResolver(), $request, $this->pendingSessionGuard());
    }

    /**
     * @return void
     */
    public function testPendingSessionResolverRefusesAnInvalidCredential(): void
    {
        $request = $this->requestWithInvalidPendingCredential();

        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused($this->pendingSessionResolver(), $request, $this->pendingSessionGuard());
    }

    /**
     * @return void
     */
    public function testPendingSessionResolverDoesNotRevalidateAnEndedSession(): void
    {
        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(
            $this->pendingSessionResolver(),
            $this->requestWithPendingCredential(),
            $this->pendingSessionGuard(),
            $this->endPendingSession(...),
        );
    }

    /**
     * A valid pending credential, or `null` (the default) for a resolver that
     * has none.
     *
     * @return ?\Illuminate\Http\Request
     */
    protected function requestWithPendingCredential(): ?Request
    {
        return null;
    }

    /**
     * End the pending session as the authentication layer does when it is
     * satisfied, expires or is revoked.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return void
     */
    protected function endPendingSession(PendingContext $pending): void {}

    /**
     * The guard the requests are for; by default the default guard.
     *
     * @return string
     */
    protected function pendingSessionGuard(): string
    {
        return Container::getInstance()->make('auth')->getDefaultDriver();
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver
     */
    abstract protected function pendingSessionResolver(): PendingSessionResolver;

    /**
     * @return \Illuminate\Http\Request
     */
    abstract protected function requestWithoutPendingCredential(): Request;

    /**
     * An invalid pending credential, or `null` for a resolver that has none.
     *
     * @return ?\Illuminate\Http\Request
     */
    abstract protected function requestWithInvalidPendingCredential(): ?Request;
}
