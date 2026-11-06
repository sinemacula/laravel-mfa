<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;

/**
 * What every `PendingSessionResolver` must guarantee, as assertions: a request
 * that carries no pending credential has no pending session, and one that
 * carries a credential that does not validate is refused by throwing, never
 * answered as having none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class PendingSessionResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A request with no pending credential has no pending session.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver  $resolver
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public static function assertNoCredentialMeansNoPendingSession(PendingSessionResolver $resolver, Request $request): void
    {
        Assert::assertNull($resolver->fromRequest($request), 'A request carrying no pending credential must have no pending session.');
    }

    /**
     * A request with a pending credential that does not validate is refused by
     * throwing a `RuntimeException`. A resolver with no pending credentials at
     * all is given no such request, and answers none for any.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver  $resolver
     * @param  ?\Illuminate\Http\Request  $request
     * @return void
     */
    public static function assertAnInvalidCredentialIsRefused(PendingSessionResolver $resolver, ?Request $request): void
    {
        if ($request === null) {
            Assert::assertNull($resolver->fromRequest(Request::create('/')), 'A resolver with no pending credentials must answer none.');

            return;
        }

        SeamAssert::refusesByThrowing(static fn () => $resolver->fromRequest($request), 'A pending credential that does not validate must be refused by throwing, not answered.');
    }
}
