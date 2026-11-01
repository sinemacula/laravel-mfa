<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;

/**
 * Names the application a request is for from its `X-Application` header, or a
 * fixed name when the header is missing, so a test can send consecutive
 * requests for different applications through one driver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HeaderApplicationResolver implements ApplicationResolver
{
    /** @var string The header naming the application. */
    public const string HEADER = 'X-Application';

    /**
     * Constructor.
     *
     * @param  string  $default
     */
    public function __construct(

        /** The application of a request without the header. */
        private string $default = 'web',
    ) {}

    /**
     * The application the request's header names, or the default one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    #[\Override]
    public function resolve(Request $request): string
    {
        $application = $request->headers->get(self::HEADER);

        return $application === null || $application === '' ? $this->default : $application;
    }

    /**
     * A request for the named application.
     *
     * @param  string  $application
     * @return \Illuminate\Http\Request
     */
    public static function requestFor(string $application): Request
    {
        $request = Request::create('/');

        $request->headers->set(self::HEADER, $application);

        return $request;
    }
}
