<?php

declare(strict_types = 1);

namespace Tests\Unit\Http\Middleware;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Http\Middleware\ExemptFromMfa;
use Symfony\Component\HttpFoundation\Response;

/**
 * Unit tests for `ExemptFromMfa`: a marker that only passes the request on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExemptFromMfa::class)]
final class ExemptFromMfaTest extends TestCase
{
    /**
     * The request goes on unchanged, and the next answer comes back.
     *
     * @return void
     */
    public function testItOnlyPassesTheRequestOn(): void
    {
        $request  = Request::create('/');
        $response = new Response('answered');

        $answer = (new ExemptFromMfa)->handle($request, static function (Request $passed) use ($request, $response): Response {
            self::assertSame($request, $passed);

            return $response;
        });

        self::assertSame($response, $answer);
        self::assertSame([], $request->attributes->all());
    }
}
