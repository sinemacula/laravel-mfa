<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Exception\RequestExceptionInterface;

/**
 * The client an action is served to, as plain values: its IP address and user
 * agent, and the facts a same-site check reads (the request's `Origin`, its
 * scheme and host, and the names of the headers it carries). The IP address is
 * what the IP throttle charges an attempt to and what events carry; any of them
 * may be unknown, as outside a request.
 *
 * `fromRequest()` is the one place it is read from a request, through the
 * request's own `ip()`, so the application's trusted proxies apply. The facts
 * are kept as the request gave them, for the seam that judges them; only the IP
 * address and the user agent reach events.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientContext
{
    /** @var ?string The client's IP address, when it is known. */
    public ?string $ip;

    /** @var ?string The client's user agent, when it is known. */
    public ?string $userAgent;

    /** @var ?string The request's `Origin` header, as it was sent, when it was. */
    public ?string $origin;

    /** @var ?string The request's scheme and host, such as `https://example.test`, when it has a host. */
    public ?string $schemeAndHost;

    /** @var list<string> The names of the request's headers whose first value is not empty, lower-cased with underscores read as hyphens; never their values. */
    public array $nonEmptyHeaders;

    /**
     * Constructor.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     * @param  ?string  $origin
     * @param  ?string  $schemeAndHost
     * @param  array<array-key, string>  $nonEmptyHeaders
     */
    public function __construct(?string $ip = null, ?string $userAgent = null, ?string $origin = null, ?string $schemeAndHost = null, array $nonEmptyHeaders = [])
    {
        $this->ip              = $ip;
        $this->userAgent       = $userAgent;
        $this->origin          = $origin;
        $this->schemeAndHost   = $schemeAndHost;
        $this->nonEmptyHeaders = array_values(array_unique(array_map(self::headerName(...), $nonEmptyHeaders)));
    }

    /**
     * A client of which nothing is known.
     *
     * @return self
     */
    public static function unknown(): self
    {
        return new self;
    }

    /**
     * The client of the request: its IP address, through the trusted proxies,
     * its user agent, its `Origin` header, its scheme and host, and the names
     * of the headers it carries a value in.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip(), $request->userAgent(), $request->headers->get('Origin'), self::schemeAndHostOf($request), self::nonEmptyHeadersOf($request));
    }

    /**
     * Determine whether the request carried a value in the named header,
     * compared as the names are kept: without case, underscores read as
     * hyphens.
     *
     * @param  string  $name
     * @return bool
     */
    public function carriesHeader(string $name): bool
    {
        return in_array(self::headerName($name), $this->nonEmptyHeaders, true);
    }

    /**
     * A header's name as it is kept: lower-cased, with underscores read as
     * hyphens, as the request's own header bag keys it.
     *
     * @param  string  $name
     * @return string
     */
    private static function headerName(string $name): string
    {
        return strtr($name, '_ABCDEFGHIJKLMNOPQRSTUVWXYZ', '-abcdefghijklmnopqrstuvwxyz');
    }

    /**
     * The request's scheme and host, or `null` when it has no host or one the
     * request refuses as untrusted or malformed. It is read off a copy, so a
     * refusal does not change what the request answers afterwards.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?string
     */
    private static function schemeAndHostOf(Request $request): ?string
    {
        $copy = clone $request;

        try {
            return $copy->getHost() === '' ? null : $copy->getSchemeAndHttpHost();
        } catch (RequestExceptionInterface) { // @phpstan-ignore catch.neverThrown
            return null;
        }
    }

    /**
     * The names of the request's headers whose first value is neither missing
     * nor empty; `0` counts as a value.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return list<string>
     */
    private static function nonEmptyHeadersOf(Request $request): array
    {
        $names = [];

        foreach ($request->headers->all() as $name => $values) {

            $first = $values[0] ?? null;

            if ($first === null || $first === '') {
                continue;
            }

            $names[] = $name;
        }

        return $names;
    }
}
