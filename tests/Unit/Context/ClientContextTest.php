<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Context\ClientContext;

/**
 * Unit tests for `ClientContext`: the client's address and user agent, and the
 * facts a same-site check reads, as a request gives them, or nothing known.
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
        self::assertNull($client->origin);
        self::assertNull($client->schemeAndHost);
        self::assertSame([], $client->nonEmptyHeaders);
        self::assertFalse($client->carriesHeader('x-csrf-token'));
    }

    /**
     * A request gives its `Origin` as sent, its scheme and host, and the names
     * of the headers whose first value is not empty, a `0` counting; never
     * their values.
     *
     * @return void
     */
    public function testARequestGivesTheFactsASameSiteCheckReads(): void
    {
        $request = Request::create('https://app.example.test/verify', 'POST', server: [
            'HTTP_ORIGIN'       => 'https://app.example.test',
            'HTTP_X_CSRF_TOKEN' => 'secret-value',
            'HTTP_X_ZERO'       => '0',
            'HTTP_X_EMPTY'      => '',
        ]);

        $client = ClientContext::fromRequest($request);

        self::assertSame('https://app.example.test', $client->origin);
        self::assertSame('https://app.example.test', $client->schemeAndHost);
        self::assertTrue($client->carriesHeader('X-CSRF-Token'));
        self::assertTrue($client->carriesHeader('x_csrf_token'));
        self::assertTrue($client->carriesHeader('x-zero'));
        self::assertFalse($client->carriesHeader('x-empty'));
        self::assertFalse($client->carriesHeader('authorization'));
        self::assertNotContains('secret-value', $client->nonEmptyHeaders);
        self::assertSame($client->nonEmptyHeaders, array_values(array_filter($client->nonEmptyHeaders, static fn (string $name): bool => $name === strtolower($name))));
    }

    /**
     * A request without an `Origin` gives none, and one whose host the request
     * refuses gives no scheme and host.
     *
     * @return void
     */
    public function testARequestWithoutAnOriginOrWithABadHostGivesNeither(): void
    {
        $request = Request::create('/', 'POST', server: ['HTTP_HOST' => 'bad host']);

        $client = ClientContext::fromRequest($request);

        self::assertNull($client->origin);
        self::assertNull($client->schemeAndHost);
    }

    /**
     * Header names given to the constructor are kept as a request's are:
     * lower-cased, underscores read as hyphens, once each, and only those that
     * are HTTP tokens.
     *
     * @return void
     */
    public function testHeaderNamesAreKeptAsARequestKeysThem(): void
    {
        $client = new ClientContext(null, null, null, null, ['X_CSRF_Token', 'x-csrf-token', 'Accept', '', 'bad name', "caf\u{e9}"]);

        self::assertSame(['x-csrf-token', 'accept'], $client->nonEmptyHeaders);
        self::assertFalse($client->carriesHeader(''));
        self::assertFalse($client->carriesHeader('bad name'));
    }

    /**
     * An origin, or a scheme and host, is kept only when it is 1 to 512
     * printable ASCII characters with no spaces, as an authentication layer's
     * own client context keeps it.
     *
     * @return void
     */
    public function testAnOriginIsKeptOnlyWhenItIsWellFormed(): void
    {
        self::assertSame('https://app.example.test', (new ClientContext(origin: 'https://app.example.test'))->origin);
        self::assertSame(str_repeat('a', 512), (new ClientContext(origin: str_repeat('a', 512)))->origin);

        foreach (['', 'https://app example.test', "https://caf\u{e9}.test", str_repeat('a', 513), "https://app.test\n"] as $malformed) {
            self::assertNull((new ClientContext(origin: $malformed))->origin);
            self::assertNull((new ClientContext(schemeAndHost: $malformed))->schemeAndHost);
        }
    }
}
