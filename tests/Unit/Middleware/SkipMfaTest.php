<?php

declare(strict_types = 1);

namespace Tests\Unit\Middleware;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Middleware\SkipMfa;

/**
 * Unit tests for the `SkipMfa` middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SkipMfaTest extends TestCase
{
    /**
     * Test handle sets skip mfa attribute and passes through.
     *
     * @return void
     */
    public function testHandleSetsSkipMfaAttributeAndPassesThrough(): void
    {
        $middleware = new SkipMfa;
        $request    = Request::create('/');
        $response   = new Response('ok');

        $seen   = null;
        $result = $middleware->handle($request, static function (Request $passed) use (&$seen, $response): Response {
            $seen = $passed;

            return $response;
        });

        self::assertTrue($request->attributes->get('skip_mfa'));
        // @SuppressWarnings("php:S3415")
        self::assertSame($request, $seen);
        self::assertSame($response, $result);
    }
}
