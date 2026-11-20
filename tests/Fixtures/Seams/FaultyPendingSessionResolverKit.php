<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Seams;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\PendingSessionResolverTests;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;

/**
 * The pending session resolver kit over a resolver said to have no pending
 * credentials that answers a pending session for every request, for running its
 * checks as PHPUnit does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class FaultyPendingSessionResolverKit extends TestCase
{
    use PendingSessionResolverTests;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver
     */
    #[\Override]
    protected function pendingSessionResolver(): PendingSessionResolver
    {
        $identity = new NonEloquentIdentity;

        return new FixedPendingSessionResolver(new PendingContext(
            $identity,
            'web',
            'pending-1',
            SignInProofs::of($identity)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addMinutes(10),
        ));
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
     * @return null
     */
    #[\Override]
    protected function requestWithInvalidPendingCredential(): null
    {
        return null;
    }
}
