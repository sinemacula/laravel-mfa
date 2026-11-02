<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Http\Request;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;

/**
 * What every `EventContextResolver` must guarantee, as an assertion: the
 * context is scalar values only, with and without an identity and a request,
 * never a model, an array or any other object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class EventContextResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Every value of the context is an integer, a string or `null`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EventContextResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public static function assertGivesScalarValuesOnly(EventContextResolver $resolver, MultiFactorAuthenticatable $identity): void
    {
        $message = 'An event context must hold integers, strings and nulls only.';

        SeamAssert::scalars($resolver->resolve($identity, Request::create('/', 'POST', server: ['REMOTE_ADDR' => '192.0.2.1'])), $message);
        SeamAssert::scalars($resolver->resolve(null, null), $message);
    }
}
