<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;

/**
 * What every `ApplicationResolver` must guarantee, as an assertion: a request
 * names one application, by a name that is not blank, the same each time it is
 * asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class ApplicationResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The request's application is named, and named the same way again.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\ApplicationResolver  $resolver
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public static function assertNamesOneApplication(ApplicationResolver $resolver, Request $request): void
    {
        $application = $resolver->resolve($request);

        Assert::assertNotSame('', trim($application), 'The application of a request must not be blank.');
        Assert::assertSame($application, $resolver->resolve($request), 'A request must name the same application each time.');
    }
}
