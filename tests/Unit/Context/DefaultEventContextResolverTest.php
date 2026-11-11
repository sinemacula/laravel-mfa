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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultEventContextResolver::class)]
final class DefaultEventContextResolverTest extends TestCase
{
    /**
     * @return void
     */
    public function testItIsBoundByDefault(): void
    {
        self::assertInstanceOf(DefaultEventContextResolver::class, $this->container()->make(EventContextResolver::class));
    }

    /**
     * The dispatcher names the application, and the sign-in is this package's
     * own id, not a session's.
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
     * @return void
     */
    public function testWithoutAnIdentityOrARequestNothingIsKnown(): void
    {
        self::assertSame(array_fill_keys(EventContext::KEYS, null), $this->resolver()->resolve(new EventSubject));
    }

    /**
     * The dispatcher names the application the operation ran through.
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
     * @return \SineMacula\Laravel\Mfa\Context\DefaultEventContextResolver
     */
    private function resolver(): DefaultEventContextResolver
    {
        return $this->container()->make(DefaultEventContextResolver::class);
    }
}
