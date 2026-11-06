<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Context\ClientContext;
use SineMacula\Laravel\Mfa\Contracts\EventContextResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Events\EventSubject;

/**
 * What every `EventContextResolver` must guarantee, as assertions: the context
 * is scalar values only, with and without an identity and a client, never a
 * model, an array or any other object; a subject naming no sign-in the resolver
 * knows leaves the session, principal and tenant unknown; and one naming a
 * sign-in it knows names its session.
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

    /**
     * A subject that names no sign-in, or one the resolver does not know,
     * leaves the session, the principal and the tenant unknown: they are never
     * filled from whichever session the process happens to serve.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EventContextResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     */
    public static function assertNamesNoSessionItIsNotGiven(EventContextResolver $resolver, MultiFactorAuthenticatable $identity): void
    {
        $client = new ClientContext('192.0.2.1', 'contract-agent');

        foreach ([null, 'contract-unknown-sign-in'] as $signIn) {

            $context = $resolver->resolve(new EventSubject($identity, 'contract-application', $signIn, $client));

            foreach (['session_id', 'principal_type', 'principal_id', 'tenant_id'] as $key) {
                Assert::assertNull($context[$key] ?? null, sprintf('A subject naming no sign-in the resolver knows must leave `%s` unknown.', $key));
            }
        }
    }

    /**
     * A subject naming a sign-in the resolver knows names its session.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EventContextResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $signIn
     * @return void
     */
    public static function assertNamesTheSessionOfAKnownSignIn(EventContextResolver $resolver, MultiFactorAuthenticatable $identity, string $application, string $signIn): void
    {
        $context = $resolver->resolve(new EventSubject($identity, $application, $signIn));

        Assert::assertNotNull($context['session_id'] ?? null, 'A subject naming a sign-in the resolver knows must name its session.');
    }
}
