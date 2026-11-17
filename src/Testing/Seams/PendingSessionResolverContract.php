<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * What every `PendingSessionResolver` must guarantee: no pending credential
 * means no pending session, and an invalid one throws rather than reads as
 * none.
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
}
