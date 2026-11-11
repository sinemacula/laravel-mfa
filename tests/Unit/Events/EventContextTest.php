<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventContext;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
#[CoversClass(Actor::class)]
final class EventContextTest extends TestCase
{
    /**
     * Pinned in order, so a renamed key fails.
     *
     * @return void
     */
    public function testTheKeysAreTheStableNames(): void
    {
        self::assertSame([
            'identity_type',
            'identity_id',
            'principal_type',
            'principal_id',
            'tenant_id',
            'application',
            'session_id',
            'ip',
            'user_agent',
        ], EventContext::KEYS);
    }

    /**
     * Anything else becomes `null`, every key is present, and unknown keys are
     * dropped.
     *
     * @return void
     */
    public function testTheAllowlistKeepsOnlyScalarIdentifiers(): void
    {
        $context = EventContext::allowlist([
            'identity_type' => 'person',
            'identity_id'   => 42,
            'tenant_id'     => 1.5,
            'session_id'    => true,
            'ip'            => new \stdClass,
            'secret'        => 'never',
            7               => 'positional',
        ]);

        self::assertSame([
            'identity_type'  => 'person',
            'identity_id'    => 42,
            'principal_type' => null,
            'principal_id'   => null,
            'tenant_id'      => null,
            'application'    => null,
            'session_id'     => null,
            'ip'             => null,
            'user_agent'     => null,
        ], $context);
    }

    /**
     * @return void
     */
    public function testAScalarKeyIsAString(): void
    {
        self::assertSame('42', EventContext::scalarKey(42));
        self::assertSame('01J', EventContext::scalarKey('01J'));
        self::assertNull(EventContext::scalarKey(null));
        self::assertNull(EventContext::scalarKey(4.2));
    }

    /**
     * Encoded as both.
     *
     * @return void
     */
    public function testAnActorIsItsTypeAndId(): void
    {
        $actor = Actor::of(new NonEloquentIdentity(identifier: 9));

        self::assertSame(NonEloquentIdentity::class, $actor->type);
        self::assertSame('9', $actor->id);
        self::assertSame(['type' => NonEloquentIdentity::class, 'id' => '9'], $actor->jsonSerialize());
    }

    /**
     * Rather than failing the change it reports.
     *
     * @return void
     */
    public function testAnActorWithAnIdentifierOfAnotherShapeHasAnEmptyId(): void
    {
        self::assertSame('', Actor::of(new NonEloquentIdentity(identifier: ['x']))->id);
    }
}
