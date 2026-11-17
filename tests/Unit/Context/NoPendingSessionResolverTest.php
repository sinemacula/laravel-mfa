<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Requirements\SignInProofs;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoPendingSessionResolver::class)]
final class NoPendingSessionResolverTest extends TestCase
{
    /**
     * @return void
     */
    public function testFindsNoPendingSessionOnARequest(): void
    {
        self::assertNull((new NoPendingSessionResolver)->fromRequest(Request::create('/'), 'web'));
    }

    /**
     * Even one it is handed.
     *
     * @return void
     */
    public function testKeepsNoPendingSession(): void
    {
        $identity = new NonEloquentIdentity;
        $pending  = new PendingContext(
            $identity,
            'web',
            'pending-1',
            SignInProofs::of($identity)->inSession('pending-1')->password(),
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addHour(),
        );

        self::assertNull((new NoPendingSessionResolver)->revalidate($pending));
    }
}
