<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;

/**
 * What every `GuardApplicationResolver` must guarantee beyond what every
 * `ApplicationResolver` does, as an assertion: a request names one application
 * through a guard, by a name that is not blank, the same each time it is asked.
 * Different guards need not name different applications.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class GuardApplicationResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The request's application through the guard is named, and named the same
     * way again.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver  $resolver
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return void
     */
    public static function assertNamesOneApplicationThroughTheGuard(GuardApplicationResolver $resolver, Request $request, string $guard): void
    {
        $application = $resolver->resolveForGuard($request, $guard);

        Assert::assertNotSame('', trim($application), 'The application of a request through a guard must not be blank.');
        Assert::assertSame($application, $resolver->resolveForGuard($request, $guard), 'A request must name the same application through a guard each time.');
    }
}
