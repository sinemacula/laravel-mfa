<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\ClientContext;

/**
 * Unit tests for `ClientContext`: the client's address and user agent, as a
 * request gives them, or nothing known.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientContext::class)]
final class ClientContextTest extends TestCase
{
    /**
     * A request gives the client's address and user agent.
     *
     * @return void
     */
    public function testARequestGivesItsAddressAndUserAgent(): void
    {
        $client = ClientContext::fromRequest(Request::create('/', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Agent/1.0']));

        self::assertSame('203.0.113.9', $client->ip);
        self::assertSame('Agent/1.0', $client->userAgent);
    }

    /**
     * An unknown client knows neither.
     *
     * @return void
     */
    public function testAnUnknownClientKnowsNothing(): void
    {
        $client = ClientContext::unknown();

        self::assertNull($client->ip);
        self::assertNull($client->userAgent);
    }
}
