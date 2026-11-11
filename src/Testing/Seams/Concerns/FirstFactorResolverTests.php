<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams\Concerns;

use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Testing\Seams\FirstFactorResolverContract;

/**
 * The `FirstFactorResolver` contract kit; each check delegates to
 * `FirstFactorResolverContract`.
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
     * @return void
     */
    public function testFirstFactorResolverAnswersOnlyTheIdentitysFirstFactor(): void
    {
        FirstFactorResolverContract::assertAnswersOnlyTheIdentitysFirstFactor($this->firstFactorResolver(), $this->signedInIdentity(), $this->firstFactorApplication());
    }

    /**
     * @return void
     */
    public function testFirstFactorResolverAnswersNothingWithoutASignIn(): void
    {
        FirstFactorResolverContract::assertAnswersNothingWithoutASignIn($this->firstFactorResolver(), $this->identityWithoutSignIn(), $this->firstFactorApplication());
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver
     */
    abstract protected function firstFactorResolver(): FirstFactorResolver;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function signedInIdentity(): MultiFactorAuthenticatable;

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    abstract protected function identityWithoutSignIn(): MultiFactorAuthenticatable;

    /**
     * @return string
     */
    abstract protected function firstFactorApplication(): string;
}
