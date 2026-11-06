<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventSubject;

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

        $client = new ClientContext('192.0.2.1', 'contract-agent');

        SeamAssert::scalars($resolver->resolve(new EventSubject($identity, 'contract-application', 'contract-sign-in', $client)), $message);
        SeamAssert::scalars($resolver->resolve(new EventSubject($identity)), $message);
        SeamAssert::scalars($resolver->resolve(new EventSubject), $message);
    }
}
