<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * What every `PendingSessionResolver` must guarantee: no pending credential
 * means no pending session, an invalid one throws rather than reads as none,
 * and a session that no longer stands does not revalidate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class PendingSessionResolverContract
{
    /**
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver  $resolver
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return void
     */
    public static function assertNoCredentialMeansNoPendingSession(PendingSessionResolver $resolver, Request $request, string $guard): void
    {
        Assert::assertNull($resolver->fromRequest($request, $guard), 'A request carrying no pending credential must have no pending session.');
    }

    /**
     * Throws a `RuntimeException`. A resolver with no pending credentials is
     * given `null` and must answer none for any request.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver  $resolver
     * @param  ?\Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return void
     */
    public static function assertAnInvalidCredentialIsRefused(PendingSessionResolver $resolver, ?Request $request, string $guard): void
    {
        if ($request === null) {
            Assert::assertNull($resolver->fromRequest(Request::create('/'), $guard), 'A resolver with no pending credentials must answer none.');

            return;
        }

        $message = 'A pending credential that does not validate must be refused by throwing, not answered.';

        SeamAssert::refusesByThrowing(static fn () => $resolver->fromRequest($request, $guard), $message);
    }

    /**
     * `$end` ends the pending session the request's credential resolves to. A
     * resolver with no pending credentials is given `null` and must answer none
     * for any request.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver  $resolver
     * @param  ?\Illuminate\Http\Request  $request
     * @param  string  $guard
     * @param  \Closure(\SineMacula\Laravel\Mfa\Context\PendingContext): void  $end
     * @return void
     */
    public static function assertAnEndedSessionDoesNotRevalidate(PendingSessionResolver $resolver, ?Request $request, string $guard, \Closure $end): void
    {
        if ($request === null) {
            Assert::assertNull($resolver->fromRequest(Request::create('/'), $guard), 'A resolver with no pending credentials must answer none.');

            return;
        }

        $pending = $resolver->fromRequest($request, $guard);

        Assert::assertNotNull($pending, 'A valid pending credential must resolve a pending session.');

        $now = $resolver->revalidate($pending);

        Assert::assertNotNull($now, 'A pending session that still stands must revalidate.');
        Assert::assertSame(self::sessionOf($pending), self::sessionOf($now), 'A pending session must revalidate as the same identity, application and session.');

        $end($pending);

        Assert::assertNull($resolver->revalidate($pending), 'A pending session that no longer stands must not revalidate.');
    }

    /**
     * @param  \SineMacula\Laravel\Mfa\Context\PendingContext  $pending
     * @return list<string>
     */
    private static function sessionOf(PendingContext $pending): array
    {
        $owner = ProofOwner::of($pending->identity);

        return [$owner->type, $owner->key, $pending->application, $pending->sessionId];
    }
}
