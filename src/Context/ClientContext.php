<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Exception\RequestExceptionInterface;

/**
 * The client an action is served to; any part may be unknown outside a request.
 * Only the IP address and user agent reach events.
 *
 * Values are cleaned as an authentication layer's client context cleans them,
 * so both answer a same-site check alike.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientContext
{
    /** @var string 1 to 512 printable ASCII characters, no spaces. */
    private const string ORIGIN_PATTERN = '/^[\x21-\x7E]{1,512}$/D';

    /** @var string An HTTP token, once normalised. */
    private const string TOKEN_PATTERN = '/^[!#$%&\'*+.^`|~0-9a-z-]+$/D';

    /** @var ?string Through the application's trusted proxies. */
    public ?string $ip;

    /** @var ?string The client's user agent, when known. */
    public ?string $userAgent;

    /** @var ?string The `Origin` header as sent, when well formed. */
    public ?string $origin;

    /** @var ?string Such as `https://example.test`. */
    public ?string $schemeAndHost;

    /** @var list<string> Normalised names of headers with a value; never the values. */
    public array $nonEmptyHeaders;

    /**
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
     * @return self
     */
    public static function unknown(): self
    {
        return new self;
    }

    /**
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip(), $request->userAgent(), $request->headers->get('Origin'), self::schemeAndHostOf($request), self::nonEmptyHeadersOf($request));
    }

    /**
     * Compared without case, with underscores read as hyphens.
     *
     * @param  string  $name
     * @return bool
     */
    public function carriesHeader(string $name): bool
    {
        return in_array(self::headerName($name), $this->nonEmptyHeaders, true);
    }

    /**
     * @param  ?string  $origin
     * @return ?string
     */
    private static function cleanOrigin(?string $origin): ?string
    {
        return $origin !== null && preg_match(self::ORIGIN_PATTERN, $origin) === 1 ? $origin : null;
    }

    /**
     * Normalised HTTP tokens, deduplicated, in the order given.
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
     * Keyed as the request's own header bag keys it.
     *
     * @param  string  $name
     * @return string
     */
    private static function headerName(string $name): string
    {
        return strtr($name, '_ABCDEFGHIJKLMNOPQRSTUVWXYZ', '-abcdefghijklmnopqrstuvwxyz');
    }

    /**
     * `null` for a missing, untrusted or malformed host. Read off a copy so a
     * refusal leaves the request's later answers unchanged.
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
     * Headers whose first value is set and not empty; `0` counts as a value.
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
