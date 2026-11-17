<?php

declare(strict_types = 1);

namespace Tests\Unit\Attempts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Attempts\Attempt;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use Tests\Fixtures\Factors\InMemoryFactor;
use Tests\Fixtures\Identities\NonEloquentIdentity;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Attempt::class)]
final class AttemptTest extends TestCase
{
    /**
     * @return void
     */
    public function testHoldsWhoIsChargedAndForWhat(): void
    {
        $identity = new NonEloquentIdentity('ext-1');
        $factor   = new InMemoryFactor;
        $client   = new ClientContext('192.0.2.7');

        $attempt = new Attempt($identity, $factor, Purpose::STEP_UP, 'web', $client);

        self::assertSame($identity, $attempt->identity);
        self::assertSame($factor, $attempt->factor);
        self::assertSame(Purpose::STEP_UP, $attempt->purpose);
        self::assertSame('web', $attempt->application);
        self::assertSame($client, $attempt->client);
    }

    /**
     * A recovery code attempt has no factor.
     *
     * @return void
     */
    public function testNeedsNoFactorApplicationOrClient(): void
    {
        $attempt = new Attempt(new NonEloquentIdentity('ext-1'), null, Purpose::SIGN_IN);

        self::assertNull($attempt->factor);
        self::assertNull($attempt->application);
        self::assertNull($attempt->client);
    }
}
