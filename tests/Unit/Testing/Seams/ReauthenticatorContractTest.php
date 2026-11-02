<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\Reauthenticator;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Seams\RefusingReauthenticator;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\ReauthenticatorTests;
use SineMacula\Laravel\Mfa\Testing\Seams\ReauthenticatorContract;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\Fixtures\Seams\FixedReauthenticator;
use Tests\Fixtures\Seams\FreshReauthenticator;
use Tests\TestCase;

/**
 * The `Reauthenticator` contract kit proves the refusing default and a
 * reauthenticator that proves the first factor again now, and rejects one that
 * answers an old proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReauthenticatorContract::class)]
#[CoversClass(RefusingReauthenticator::class)]
final class ReauthenticatorContractTest extends TestCase
{
    use ReauthenticatorTests;

    /**
     * The default refuses whoever asks.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheDefaultRefuses(): void
    {
        self::assertNull($this->reauthenticator()->reauthenticate($this->reauthenticatingIdentity(), 'web'));
    }

    /**
     * A reauthenticator that has just proved the first factor passes the kit.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAcceptsAFreshReauthentication(): void
    {
        $identity = $this->reauthenticatingIdentity();

        ReauthenticatorContract::assertNeverAnswersAProofItDidNotJustMake(new FreshReauthenticator($this->container()->make(ProofStore::class)), $identity, 'web');
    }

    /**
     * The kit rejects a reauthentication made long ago.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRejectsAnOldReauthentication(): void
    {
        $identity = $this->reauthenticatingIdentity();

        $this->expectException(AssertionFailedError::class);

        ReauthenticatorContract::assertNeverAnswersAProofItDidNotJustMake(new FreshReauthenticator($this->container()->make(ProofStore::class), 600), $identity, 'web');
    }

    /**
     * Rows of a reauthentication the kit must reject: of another kind, of
     * another identity, on another application, and dated in the future.
     *
     * @return iterable<string, array{\Closure(\Tests\Fixtures\Requirements\SignInProofs): \SineMacula\Laravel\Mfa\Proofs\Proof}>
     */
    public static function wrongReauthentications(): iterable
    {
        yield 'a first factor' => [static fn (SignInProofs $proofs): Proof => $proofs->password()];
        yield 'another identity' => [static fn (SignInProofs $proofs): Proof => $proofs->ofIdentity('someone-else')->reauthentication()];
        yield 'another application' => [static fn (SignInProofs $proofs): Proof => $proofs->onApplication('api')->reauthentication()];
        yield 'the future' => [static fn (SignInProofs $proofs): Proof => $proofs->reauthentication(-60)];
    }

    /**
     * The kit rejects a reauthenticator that answers anything but the
     * identity's own reauthentication on the application, made by now.
     *
     * @param  \Closure(\Tests\Fixtures\Requirements\SignInProofs): \SineMacula\Laravel\Mfa\Proofs\Proof  $proof
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('wrongReauthentications')]
    public function testRejectsAWrongReauthentication(\Closure $proof): void
    {
        $identity = $this->reauthenticatingIdentity();

        $this->expectException(AssertionFailedError::class);

        ReauthenticatorContract::assertNeverAnswersAProofItDidNotJustMake(new FixedReauthenticator($proof(SignInProofs::of($identity))), $identity, 'web');
    }

    /**
     * The bound default.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\Reauthenticator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function reauthenticator(): Reauthenticator
    {
        return $this->container()->make(Reauthenticator::class);
    }

    /**
     * A person signed in on the application.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function reauthenticatingIdentity(): MultiFactorAuthenticatable
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->firstOrCreate(['email' => 'reauthenticating@example.test']);

        $this->container()->make(ProofStore::class)->begin($user, 'web', 'sign-in-1');

        return $user;
    }

    /**
     * The application.
     *
     * @return string
     */
    #[\Override]
    protected function reauthenticationApplication(): string
    {
        return 'web';
    }
}
