<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventContext;
use SineMacula\Laravel\Mfa\Events\EventSubject;
use Tests\Fixtures\Identities\NonEloquentIdentity;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Unit tests for `DefaultEventContextResolver`, the event context without an
 * authentication layer: the identity, the application and the request, never
 * the Laravel session's id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultEventContextResolver::class)]
final class DefaultEventContextResolverTest extends TestCase
{
    /**
     * It is the resolver bound by default.
     *
     * @return void
     */
    public function testItIsBoundByDefault(): void
    {
        self::assertInstanceOf(DefaultEventContextResolver::class, $this->container()->make(EventContextResolver::class));
    }

    /**
     * The identity's type and id, and the client's address and user agent; no
     * application, which the dispatcher names, and no principal, tenant or
     * session, the sign-in being this package's own id and no session's.
     *
     * @return void
     */
    public function testResolvesTheIdentityAndTheClient(): void
    {
        $context = $this->resolver()->resolve(new EventSubject(new NonEloquentIdentity(identifier: 5), 'web', 'sign-in-1', new ClientContext('203.0.113.9', 'Mozilla/5.0')));

        self::assertSame([
            'identity_type'  => NonEloquentIdentity::class,
            'identity_id'    => '5',
            'principal_type' => null,
            'principal_id'   => null,
            'tenant_id'      => null,
            'application'    => null,
            'session_id'     => null,
            'ip'             => '203.0.113.9',
            'user_agent'     => 'Mozilla/5.0',
        ], $context);
    }

    /**
     * An Eloquent identity is recorded by its morph class.
     *
     * @return void
     */
    public function testAnEloquentIdentityIsRecordedByItsMorphClass(): void
    {
        $user = new TestUser;
        $user->setAttribute('id', 3);

        $context = $this->resolver()->resolve(new EventSubject($user));

        self::assertSame($user->getMorphClass(), $context['identity_type']);
        self::assertSame('3', $context['identity_id']);
    }

    /**
     * Without an identity or a request, nothing is known.
     *
     * @return void
     */
    public function testWithoutAnIdentityOrARequestNothingIsKnown(): void
    {
        self::assertSame(array_fill_keys(EventContext::KEYS, null), $this->resolver()->resolve(new EventSubject));
    }

    /**
     * The application is never read from a resolver: the dispatcher names the
     * one the operation ran through.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoApplicationIsRead(): void
    {
        $resolver = \Mockery::mock(ApplicationResolver::class);

        $resolver->shouldNotReceive('resolve');

        $this->container()->instance(ApplicationResolver::class, $resolver);

        self::assertNull($this->resolver()->resolve(new EventSubject(null, 'web', null, new ClientContext('203.0.113.9')))['application']);
    }

    /**
     * Resolve the resolver.
     *
     * @return \SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver
     */
    private function resolver(): DefaultEventContextResolver
    {
        return $this->container()->make(DefaultEventContextResolver::class);
    }
}
