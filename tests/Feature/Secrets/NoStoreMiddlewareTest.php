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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoStore::class)]
final class NoStoreMiddlewareTest extends TestCase
{
    /** @var string */
    private const string SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /**
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
     * @return void
     */
    public function testReplacesTheCachingTheRouteAllowed(): void
    {
        $response = $this->get('secrets/cached');

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
        self::assertFalse($response->baseResponse->headers->hasCacheControlDirective('public'));
    }

    /**
     * @return void
     */
    public function testLeavesOtherRoutesAlone(): void
    {
        $response = $this->get('secrets/plain');

        $response->assertOk();

        self::assertFalse($response->baseResponse->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * @return void
     */
    public function testTheResponseHelperRevealsTheSecretWithoutStoring(): void
    {
        $response = $this->getJson('secrets/revealed');

        $response->assertExactJson(['secret' => self::SECRET]);

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
    }

    /**
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
