<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Events\Actor;
use SineMacula\Laravel\Mfa\Events\EventContext;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * Unit tests for `EventContext`, the allowlist every event's context is cut
 * down to, and `Actor`, who took an action by type and id.
 *
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
     * The context's keys, in order, so a renamed key fails.
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
     * Integers and strings are kept, anything else becomes `null`, every key is
     * present, and keys outside the allowlist are dropped.
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
     * An identifier is a string when it is an integer or a string, and `null`
     * otherwise.
     *
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
     * An actor is recorded by its type and id, and encodes as both.
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
     * An actor whose identifier is of another shape is recorded with an empty
     * id rather than failing the change it reports.
     *
     * @return void
     */
    public function testAnActorWithAnIdentifierOfAnotherShapeHasAnEmptyId(): void
    {
        self::assertSame('', Actor::of(new NonEloquentIdentity(identifier: ['x']))->id);
    }
}
