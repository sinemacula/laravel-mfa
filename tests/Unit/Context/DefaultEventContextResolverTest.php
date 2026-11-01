<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Events\EventContext;
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
     * The identity by type and id, and the request's IP address and user agent;
     * no principal, tenant or session.
     *
     * @return void
     */
    public function testResolvesTheIdentityAndTheRequest(): void
    {
        $request = Request::create('/', 'GET', server: ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Mozilla/5.0']);
        $request->setLaravelSession($this->container()->make('session.store'));

        $context = $this->resolver()->resolve(new NonEloquentIdentity(identifier: 5), $request);

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

        $context = $this->resolver()->resolve($user, null);

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
        self::assertSame(array_fill_keys(EventContext::KEYS, null), $this->resolver()->resolve(null, null));
    }

    /**
     * A bound application resolver names the request's application; without a
     * request it is not asked.
     *
     * @return void
     */
    public function testABoundApplicationResolverNamesTheApplication(): void
    {
        $this->container()->instance(ApplicationResolver::class, new class implements ApplicationResolver {
            /**
             * Name the application after the request's path.
             *
             * @param  \Illuminate\Http\Request  $request
             * @return string
             */
            #[\Override]
            public function resolve(Request $request): string
            {
                return 'app-' . $request->path();
            }
        });

        self::assertSame('app-admin', $this->resolver()->resolve(null, Request::create('/admin'))['application']);
        self::assertNull($this->resolver()->resolve(null, null)['application']);
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
