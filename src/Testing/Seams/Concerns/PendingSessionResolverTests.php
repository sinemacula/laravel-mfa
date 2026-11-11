<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use Illuminate\Http\Request;
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
        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession($this->pendingSessionResolver(), $this->requestWithoutPendingCredential());
    }

    /**
     * @return void
     */
    public function testPendingSessionResolverRefusesAnInvalidCredential(): void
    {
        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused($this->pendingSessionResolver(), $this->requestWithInvalidPendingCredential());
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
