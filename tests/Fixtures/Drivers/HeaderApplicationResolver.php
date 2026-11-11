<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;

/**
 * Names the application from the `X-Application` header, so consecutive
 * requests through one driver can be for different applications.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HeaderApplicationResolver implements ApplicationResolver
{
    /** @var string */
    public const string HEADER = 'X-Application';

    /**
     * @param  string  $default
     */
    public function __construct(

        /** For a request without the header. */
        private string $default = 'web',
    ) {}

    /**
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
