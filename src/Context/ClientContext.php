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
 * are cleaned as an authentication layer's own client context cleans them (an
 * origin of up to 512 printable characters, header names that are HTTP tokens),
 * so the two answer a same-site check alike, and are otherwise kept for the
 * seam that judges them; only the IP address and the user agent reach events.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientContext
{
    /** @var string What an origin, or a scheme and host, must be to be kept: 1 to 512 printable ASCII characters, no spaces. */
    private const string ORIGIN_PATTERN = '/^[\x21-\x7E]{1,512}$/D';

    /** @var string What a header's name must be, once normalised, to be kept: an HTTP token. */
    private const string TOKEN_PATTERN = '/^[!#$%&\'*+.^`|~0-9a-z-]+$/D';

    /** @var ?string The client's IP address, when it is known. */
    public ?string $ip;

    /** @var ?string The client's user agent, when it is known. */
    public ?string $userAgent;

    /** @var ?string The request's `Origin` header, as it was sent, when it was and is well formed. */
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
        $this->origin          = self::cleanOrigin($origin);
        $this->schemeAndHost   = self::cleanOrigin($schemeAndHost);
        $this->nonEmptyHeaders = self::headerNames($nonEmptyHeaders);
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
     * An origin, or a scheme and host, kept only when it is 1 to 512 printable
     * ASCII characters with no spaces; anything else is not known.
     *
     * @param  ?string  $origin
     * @return ?string
     */
    private static function cleanOrigin(?string $origin): ?string
    {
        return $origin !== null && preg_match(self::ORIGIN_PATTERN, $origin) === 1 ? $origin : null;
    }

    /**
     * The header names as they are kept: normalised, each an HTTP token, once
     * each, in the order given.
     *
     * @param  array<array-key, string>  $names
     * @return list<string>
     */
    private static function headerNames(array $names): array
    {
        $normalised = array_map(self::headerName(...), $names);

        return array_values(array_unique(array_filter($normalised, static fn (string $name): bool => preg_match(self::TOKEN_PATTERN, $name) === 1)));
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
