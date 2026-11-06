<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Context;

use Illuminate\Http\Request;

/**
 * The client an action is served to: its IP address and user agent, as plain
 * values. The IP address is what the IP throttle charges an attempt to and what
 * events carry; either may be unknown, as outside a request.
 *
 * `fromRequest()` is the one place it is read from a request, through the
 * request's own `ip()`, so the application's trusted proxies apply.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientContext
{
    /**
     * Constructor.
     *
     * @param  ?string  $ip
     * @param  ?string  $userAgent
     */
    public function __construct(

        /** The client's IP address, when it is known. */
        public ?string $ip = null,

        /** The client's user agent, when it is known. */
        public ?string $userAgent = null,
    ) {}

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
     * and its user agent.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        return new self($request->ip(), $request->userAgent());
    }
}
