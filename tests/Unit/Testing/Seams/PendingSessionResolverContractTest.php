<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingSessionResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingSessionResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SeamAssert;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
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
     * @return void
     */
    public function testAcceptsAResolverThatRefusesAnInvalidCredential(): void
    {
        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver(invalid: true), Request::create('/'));
    }

    /**
     * @return void
     */
    public function testRejectsAPendingSessionWithoutACredential(): void
    {
        $identity = new NonEloquentIdentity;
        $pending  = new PendingContext(
            $identity,
            'web',
            'pending-1',
            SignInProofs::of($identity)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        );

        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession(new FixedPendingSessionResolver($pending), Request::create('/'));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatAnswersAnInvalidCredential(): void
    {
        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver, Request::create('/'));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverWithoutCredentialsThatAnswersOne(): void
    {
        $identity = new NonEloquentIdentity;
        $pending  = new PendingContext(
            $identity,
            'web',
            'pending-1',
            SignInProofs::of($identity)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        );

        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver($pending), null);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function pendingSessionResolver(): PendingSessionResolver
    {
        return $this->container()->make(PendingSessionResolver::class);
    }

    /**
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function requestWithoutPendingCredential(): Request
    {
        return Request::create('/');
    }

    /**
     * The default knows no pending credentials.
     *
     * @return null
     */
    #[\Override]
    protected function requestWithInvalidPendingCredential(): null
    {
        return null;
    }
}
