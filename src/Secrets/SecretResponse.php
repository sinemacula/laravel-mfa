<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Secrets;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sends one-time secrets with `Cache-Control: no-store` so no browser or proxy
 * keeps the only response that shows them.
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
     * Reveals every `RevealedSecret` in the data, at any depth.
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
     * Replaces any caching headers the response had.
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
