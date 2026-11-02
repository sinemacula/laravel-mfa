<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\FirstFactorResolverContract;

/**
 * The `FirstFactorResolver` contract kit: it answers nothing, or a first factor
 * of the identity on the application not dated in the future, and nothing for
 * an identity with no sign-in.
 *
 * A test case proves its implementation by using this trait and implementing
 * the hooks; each check delegates to `FirstFactorResolverContract`.
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
trait FirstFactorResolverTests
{
    /**
     * A signed-in identity is answered nothing, or its own first factor on the
     * application.
     *
     * @return void
     */
    public function testFirstFactorResolverAnswersOnlyTheIdentitysFirstFactor(): void
    {
        FirstFactorResolverContract::assertAnswersOnlyTheIdentitysFirstFactor($this->firstFactorResolver(), $this->signedInIdentity(), $this->firstFactorApplication());
    }

    /**
     * An identity with no sign-in has no first factor.
     *
     * @return void
     */
    public function testFirstFactorResolverAnswersNothingWithoutASignIn(): void
    {
        FirstFactorResolverContract::assertAnswersNothingWithoutASignIn($this->firstFactorResolver(), $this->identityWithoutSignIn(), $this->firstFactorApplication());
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver
     */
    abstract protected function firstFactorResolver(): FirstFactorResolver;

    /**
     * An identity signed in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function signedInIdentity(): MultiFactorAuthenticatable;

    /**
     * An identity with no sign-in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function identityWithoutSignIn(): MultiFactorAuthenticatable;

    /**
     * The application asked about.
     *
     * @return string
     */
    abstract protected function firstFactorApplication(): string;
}
