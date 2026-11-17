<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\EventContextResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\EventContextResolverContract;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Seams\MappedSessionContextResolver;

/**
 * A resolver that knows a sign-in passes the kit, naming that sign-in's session
 * and no other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContextResolverContract::class)]
#[CoversTrait(EventContextResolverTests::class)]
final class EventContextResolverContractTest extends TestCase
{
    use EventContextResolverTests;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\EventContextResolver
     */
    #[\Override]
    protected function eventContextResolver(): EventContextResolver
    {
        return new MappedSessionContextResolver;
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    #[\Override]
    protected function eventIdentity(): MultiFactorAuthenticatable
    {
        return new NonEloquentIdentity;
    }

    /**
     * @return array{0: string, 1: string}
     */
    protected function knownEventSignIn(): array
    {
        return [MappedSessionContextResolver::APPLICATION, MappedSessionContextResolver::SIGN_IN];
    }
}
