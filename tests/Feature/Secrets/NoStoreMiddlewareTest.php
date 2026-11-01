<?php

declare(strict_types = 1);

namespace Tests\Feature\Secrets;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Secrets\NoStore;
use SineMacula\Laravel\Mfa\Secrets\RevealedSecret;
use SineMacula\Laravel\Mfa\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * Tests for the `mfa.no-store` middleware through the HTTP kernel: every
 * response of the routes it is placed on is sent with `no-store`, and other
 * routes are left as they are.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoStore::class)]
final class NoStoreMiddlewareTest extends TestCase
{
    /** @var string A TOTP secret. */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /**
     * The package aliases the middleware as `mfa.no-store` when it boots.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testThePackageAliasesTheMiddleware(): void
    {
        /** @var \Illuminate\Routing\Router $router */
        $router = $this->container()->make(Router::class);

        self::assertSame(NoStore::class, $router->getMiddleware()['mfa.no-store'] ?? null);
    }

    /**
     * A response of a route the middleware is placed on is sent with
     * `no-store`.
     *
     * @return void
     */
    public function testSendsTheRoutesResponsesWithoutStoring(): void
    {
        $response = $this->get('secrets/enroll');

        $response->assertOk();
        $response->assertHeader('Pragma', 'no-cache');

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * Caching the route allowed is replaced.
     *
     * @return void
     */
    public function testReplacesTheCachingTheRouteAllowed(): void
    {
        $response = $this->get('secrets/cached');

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
        self::assertFalse($response->baseResponse->headers->hasCacheControlDirective('public'));
    }

    /**
     * A route without the middleware is left as it is.
     *
     * @return void
     */
    public function testLeavesOtherRoutesAlone(): void
    {
        $response = $this->get('secrets/plain');

        $response->assertOk();

        self::assertFalse($response->baseResponse->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * A secret revealed through the response helper reaches the client, and
     * only in a response that is never stored.
     *
     * @return void
     */
    public function testTheResponseHelperRevealsTheSecretWithoutStoring(): void
    {
        $response = $this->getJson('secrets/revealed');

        $response->assertExactJson(['secret' => self::SECRET]);

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * Define the routes the tests call.
     *
     * @param  \Illuminate\Routing\Router  $router
     * @return void
     */
    #[\Override]
    protected function defineRoutes(mixed $router): void
    {
        $router->get('secrets/enroll', static fn (): JsonResponse => new JsonResponse(['started' => true]))->middleware('mfa.no-store');
        $router->get('secrets/cached', static fn (): Response => new Response('', 200, ['Cache-Control' => 'public, max-age=3600']))->middleware('mfa.no-store');
        $router->get('secrets/plain', static fn (): JsonResponse => new JsonResponse(['started' => true]));
        $router->get('secrets/revealed', static fn (): JsonResponse => SecretResponse::json(['secret' => new RevealedSecret(self::SECRET)]));
    }
}
