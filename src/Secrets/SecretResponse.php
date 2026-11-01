<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends the secrets the package returns once, and nothing else, in a response
 * no cache keeps.
 *
 * `json()` reveals every `RevealedSecret` in the body, at any depth, and sends
 * it with `Cache-Control: no-store` and `Pragma: no-cache`, so neither a
 * browser nor a proxy stores the one response that shows them.
 * `withoutStoring()` sets the same headers on any response, replacing whatever
 * caching it allowed; the `mfa.no-store` middleware applies it to every
 * response of the routes it is placed on, which also covers a secret a route
 * reveals itself.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SecretResponse
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A JSON response of the data with every secret in it revealed, never
     * stored.
     *
     * @param  array<array-key, mixed>  $data
     * @param  int  $status
     * @param  array<string, list<string>|string>  $headers
     * @return \Illuminate\Http\JsonResponse
     */
    public static function json(array $data, int $status = 200, array $headers = []): JsonResponse
    {
        return self::withoutStoring(new JsonResponse(self::reveal($data), $status, $headers));
    }

    /**
     * The response, sent with `Cache-Control: no-store` and `Pragma: no-cache`
     * in place of any caching it allowed.
     *
     * @template TResponse of \Symfony\Component\HttpFoundation\Response
     *
     * @param  TResponse  $response
     * @return TResponse
     */
    public static function withoutStoring(Response $response): Response
    {
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }

    /**
     * The data with every secret in it, at any depth, replaced by its
     * plaintext.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private static function reveal(array $data): array
    {
        return array_map(static fn (mixed $value): mixed => match (true) {
            $value instanceof RevealedSecret => $value->reveal(),
            is_array($value)                 => self::reveal($value),
            default                          => $value,
        }, $data);
    }
}
