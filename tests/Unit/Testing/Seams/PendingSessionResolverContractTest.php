<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingSessionResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\PendingSessionResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\SeamAssert;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Context\RecordingPendingSessionResolver;
use Tests\Fixtures\Context\RequestAttributePendingSessionResolver;
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
#[CoversTrait(PendingSessionResolverTests::class)]
final class PendingSessionResolverContractTest extends TestCase
{
    use PendingSessionResolverTests;

    /**
     * @return void
     */
    public function testAcceptsAResolverThatRefusesAnInvalidCredential(): void
    {
        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver(invalid: true), Request::create('/'), 'web');
    }

    /**
     * @return void
     */
    public function testRejectsAPendingSessionWithoutACredential(): void
    {
        $pending = self::pendingSession();

        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession(new FixedPendingSessionResolver($pending), Request::create('/'), 'web');
    }

    /**
     * The check asks for the guard it is given.
     *
     * @return void
     */
    public function testTheCheckAsksForTheGuardGiven(): void
    {
        $resolver = new FixedPendingSessionResolver(self::pendingSession('admin'), guard: 'admin');

        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession($resolver, Request::create('/'), 'web');

        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertNoCredentialMeansNoPendingSession($resolver, Request::create('/'), 'admin');
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatAnswersAnInvalidCredential(): void
    {
        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver, Request::create('/'), 'web');
    }

    /**
     * @return void
     */
    public function testRejectsAResolverWithoutCredentialsThatAnswersOne(): void
    {
        $pending = self::pendingSession();

        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertAnInvalidCredentialIsRefused(new FixedPendingSessionResolver($pending), null, 'web');
    }

    /**
     * @return void
     */
    public function testAcceptsAResolverThatDropsAnEndedSession(): void
    {
        $request = $this->servedRequestHolding(self::pendingSession());

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(new RequestAttributePendingSessionResolver, $request, 'web', self::endSession(...));
    }

    /**
     * So a kit given a credential but no way to end its session fails.
     *
     * @return void
     */
    public function testTheDefaultEndHookEndsNothing(): void
    {
        $request = $this->servedRequestHolding(self::pendingSession());

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A pending session that no longer stands must not revalidate.');

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(new RequestAttributePendingSessionResolver, $request, 'web', $this->endPendingSession(...));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatRevalidatesAnEndedSession(): void
    {
        $resolver = new RecordingPendingSessionResolver(self::pendingSession());

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A pending session that no longer stands must not revalidate.');

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate($resolver, Request::create('/'), 'web', self::endSession(...));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatRevalidatesAsAnotherSession(): void
    {
        $request = Request::create('/');

        $request->attributes->set(RequestAttributePendingSessionResolver::ATTRIBUTE, self::pendingSession());

        $this->servedRequestHolding(self::pendingSession('admin'));

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('as the same identity, application and session');

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(new RequestAttributePendingSessionResolver, $request, 'web', self::endSession(...));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatDropsAStandingSession(): void
    {
        $request = Request::create('/');

        $request->attributes->set(RequestAttributePendingSessionResolver::ATTRIBUTE, self::pendingSession());

        $this->servedRequestHolding(null);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A pending session that still stands must revalidate.');

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(new RequestAttributePendingSessionResolver, $request, 'web', self::endSession(...));
    }

    /**
     * @return void
     */
    public function testRejectsAResolverThatFindsNoSessionForAValidCredential(): void
    {
        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A valid pending credential must resolve a pending session.');

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(new RequestAttributePendingSessionResolver, Request::create('/'), 'web', self::endSession(...));
    }

    /**
     * @return void
     */
    public function testTheRevalidationCheckRejectsAResolverWithoutCredentialsThatAnswersOne(): void
    {
        $this->expectException(AssertionFailedError::class);

        PendingSessionResolverContract::assertAnEndedSessionDoesNotRevalidate(new FixedPendingSessionResolver(self::pendingSession()), null, 'web', self::endSession(...));
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

    /**
     * The request being served, holding the pending session, or none.
     *
     * @param  ?\SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return \Illuminate\Http\Request
     */
    private function servedRequestHolding(?PendingContext $pending): Request
    {
        $request = Request::create('/');

        $request->attributes->set(RequestAttributePendingSessionResolver::ATTRIBUTE, $pending);

        $this->container()->instance('request', $request);

        return $request;
    }

    /**
     * Ends it on the request being served.
     *
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private static function endSession(PendingContext $pending): void
    {
        Container::getInstance()->make('request')->attributes->remove(RequestAttributePendingSessionResolver::ATTRIBUTE);
    }

    /**
     * @param  string  $application
     * @return \SineMacula\Laravel\Mfa\Context\PendingContext
     */
    private static function pendingSession(string $application = 'web'): PendingContext
    {
        $identity = new NonEloquentIdentity;

        return new PendingContext(
            $identity,
            $application,
            'pending-1',
            SignInProofs::of($identity)->onApplication($application)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        );
    }
}
