<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Testing\Seams\FirstFactorResolverContract;
use SineMacula\Laravel\Mfa\Testing\Seams\FirstFactorResolverTests;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * The `FirstFactorResolver` contract kit proves the declared first factor, and
 * rejects a resolver that answers another identity's first factor or one for
 * an identity with no sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FirstFactorResolverContract::class)]
#[CoversClass(DeclaredFirstFactorResolver::class)]
final class FirstFactorResolverContractTest extends TestCase
{
    use FirstFactorResolverTests;

    /**
     * Declare a password first factor on the application.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('mfa.applications.web', ['first_factor' => ['method' => 'password', 'channel' => 'password']]);
    }

    /**
     * The kit rejects a resolver that answers another identity's first factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsAnotherIdentitysFirstFactor(): void
    {
        $resolver = new FixedFirstFactorResolver(SignInProofs::of($this->identityWithoutSignIn())->password());

        $this->expectException(AssertionFailedError::class);

        FirstFactorResolverContract::assertAnswersOnlyTheIdentitysFirstFactor($resolver, $this->signedInIdentity(), 'web');
    }

    /**
     * The kit rejects a resolver that answers for an identity with no sign-in.
     *
     * @return void
     */
    public function testRejectsAFirstFactorWithoutASignIn(): void
    {
        $identity = $this->identityWithoutSignIn();

        $this->expectException(AssertionFailedError::class);

        FirstFactorResolverContract::assertAnswersNothingWithoutASignIn(new FixedFirstFactorResolver(SignInProofs::of($identity)->password()), $identity, 'web');
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function firstFactorResolver(): FirstFactorResolver
    {
        return $this->container()->make(FirstFactorResolver::class);
    }

    /**
     * A person signed in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function signedInIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->firstOrCreate(['email' => 'signed-in@example.test']);

        $this->container()->make(ProofStore::class)->begin($user, 'web', SignInProofs::SESSION);

        return $user;
    }

    /**
     * A person with no sign-in.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     */
    protected function identityWithoutSignIn(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser */
        return TestUser::query()->firstOrCreate(['email' => 'signed-out@example.test']);
    }

    /**
     * The application.
     *
     * @return string
     */
    protected function firstFactorApplication(): string
    {
        return 'web';
    }
}
