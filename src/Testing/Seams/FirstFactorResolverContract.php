<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * What every `FirstFactorResolver` must guarantee, as assertions: it answers
 * nothing, or a first factor of the identity on the application, made no later
 * than now, and nothing for an identity with no sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class FirstFactorResolverContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The answer is `null`, or a first factor bound to the identity and the
     * application, made no later than now.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertAnswersOnlyTheIdentitysFirstFactor(FirstFactorResolver $resolver, MultiFactorAuthenticatable $identity, string $application): void
    {
        $proof = $resolver->resolve($identity, $application);

        Assert::assertTrue($proof === null || $proof->kind === ProofKind::FIRST_FACTOR, 'A first factor resolver must answer nothing or a first factor proof.');

        if ($proof === null) {
            return;
        }

        Assert::assertTrue(ProofOwner::of($identity)->owns($proof->binding), 'The first factor must be bound to the identity asked about.');
        Assert::assertSame($application, $proof->binding->application, 'The first factor must be bound to the application asked about.');
        Assert::assertTrue($proof->provedAt->lessThanOrEqualTo(CarbonImmutable::now()), 'The first factor must not be dated in the future.');
    }

    /**
     * An identity with no sign-in on the application has no first factor.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver  $resolver
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     */
    public static function assertAnswersNothingWithoutASignIn(FirstFactorResolver $resolver, MultiFactorAuthenticatable $identity, string $application): void
    {
        Assert::assertNull($resolver->resolve($identity, $application), 'An identity with no sign-in must have no first factor.');
    }
}
