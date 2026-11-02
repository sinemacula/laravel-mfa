<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingSessionResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingSessionResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\SeamAssert;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * The `PendingSessionResolver` contract kit proves the default, which knows no
 * pending sessions, and a resolver that refuses a credential that does not
 * validate; it rejects one that finds a pending session in every request, and
 * one that answers none for a credential it should refuse.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSessionResolverContract::class)]
#[CoversClass(SeamAssert::class)]
#[CoversClass(NoPendingSessionResolver::class)]
final class PendingSessionResolverContractTest extends TestCase
{
    use PendingSessionResolverTests;

    /**
     * A resolver that refuses an invalid credential passes the kit.
     *
     * @return void
     */
    public function testAcceptsAResolverThatRefusesAnInvalidCredential(): void
    {
        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver(invalid: true), Request::create('/'));
    }

    /**
     * The kit rejects a resolver that finds a pending session in a request
     * that carries no credential.
     *
     * @return void
     */
    public function testRejectsAPendingSessionWithoutACredential(): void
    {
        $identity = new NonEloquentIdentity;
        $pending  = new PendingContext($identity, 'web', 'pending-1', SignInProofs::of($identity)->inSession('pending-1')->password(), Requirement::none(), [PendingAction::VERIFY]);

        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession(new FixedPendingSessionResolver($pending), Request::create('/'));
    }

    /**
     * The kit rejects a resolver that answers none for a credential that does
     * not validate.
     *
     * @return void
     */
    public function testRejectsAResolverThatAnswersAnInvalidCredential(): void
    {
        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver, Request::create('/'));
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function pendingSessionResolver(): PendingSessionResolver
    {
        return $this->container()->make(PendingSessionResolver::class);
    }

    /**
     * A request with no pending credential.
     *
     * @return \Illuminate\Http\Request
     */
    protected function requestWithoutPendingCredential(): Request
    {
        return Request::create('/');
    }

    /**
     * None: the default knows no pending credentials.
     *
     * @return ?\Illuminate\Http\Request
     */
    protected function requestWithInvalidPendingCredential(): ?Request
    {
        return null;
    }
}
