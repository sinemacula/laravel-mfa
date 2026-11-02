<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Context\PendingContext;
use SineMacula\Laravel\Mfa\Context\SessionFirstFactor;
use SineMacula\Laravel\Mfa\Contracts\FirstFactorResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\PendingAction;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `SessionFirstFactor`: a session's first factor comes from the
 * pending session, the proof store, or a trusted answer of the bound resolver,
 * and from nowhere else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionFirstFactor::class)]
final class SessionFirstFactorTest extends TestCase
{
    /**
     * The latest first factor the store records for the sign-in is the
     * session's, and the resolver is not asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheStoresLatestFirstFactorComesFirst(): void
    {
        $user     = $this->signIn();
        $proofs   = SignInProofs::of($user);
        $resolver = new FixedFirstFactorResolver($proofs->externalProvider());
        $latest   = $proofs->passkey(true);

        $this->container()->instance(FirstFactorResolver::class, $resolver);

        $this->store()->record($proofs->password(60));
        $this->store()->record($latest);
        $this->store()->record($proofs->totp());

        self::assertEquals($latest, $this->firstFactors()->current($user, 'web'));
        self::assertCount(3, $this->firstFactors()->proofs($user, 'web'));
        self::assertSame(0, $resolver->asked);
    }

    /**
     * Without one in the store, the resolver's first factor counts when it is
     * trusted, and is put ahead of the recorded proofs.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testATrustedResolvedFirstFactorIsUsed(): void
    {
        $user   = $this->signIn();
        $proofs = SignInProofs::of($user);
        $first  = $proofs->password(60);

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver($first));
        $this->store()->record($proofs->totp());

        self::assertEquals($first, $this->firstFactors()->current($user, 'web'));
        self::assertSame(
            [ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR],
            array_map(static fn (Proof $proof): ProofKind => $proof->kind, $this->firstFactors()->proofs($user, 'web')),
        );
    }

    /**
     * A resolved first factor of another sign-in, a future one, or one of an
     * earlier generation is not trusted.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnUntrustedResolvedFirstFactorIsNotUsed(): void
    {
        $user   = $this->signIn();
        $proofs = SignInProofs::of($user);

        foreach ([$proofs->inSession('elsewhere')->password(), $proofs->password(-60), $proofs->underGeneration(1)->password(), $proofs->reauthentication()] as $untrusted) {
            $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver($untrusted));

            self::assertNull($this->firstFactors()->current($user, 'web'));
            self::assertSame([], $this->firstFactors()->proofs($user, 'web'));
        }
    }

    /**
     * Without a sign-in there is no first factor and no proof.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutASignInThereIsNone(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'signed-out@example.test']);

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver(SignInProofs::of($user)->password()));

        self::assertNull($this->firstFactors()->current($user, 'web'));
        self::assertSame([], $this->firstFactors()->proofs($user, 'web'));
    }

    /**
     * A binding of the current sign-in has its first factor; one of another
     * session or another identity has none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABindingOfTheCurrentSignInHasItsFirstFactor(): void
    {
        $user  = $this->signIn();
        $first = SignInProofs::of($user)->password();
        $owner = ProofOwner::of($user);

        $this->store()->record($first);

        self::assertEquals($first, $this->firstFactors()->forBinding($user, new ProofBinding($owner->type, $owner->key, 'web', SignInProofs::SESSION, Purpose::STEP_UP)));
        self::assertNull($this->firstFactors()->forBinding($user, new ProofBinding($owner->type, $owner->key, 'web', 'elsewhere', Purpose::STEP_UP)));
        self::assertNull($this->firstFactors()->forBinding($user, new ProofBinding($owner->type, 'someone-else', 'web', SignInProofs::SESSION, Purpose::STEP_UP)));
    }

    /**
     * A binding of the request's pending session has the pending session's
     * first factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABindingOfThePendingSessionHasItsFirstFactor(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user  = TestUser::query()->create(['email' => 'pending@example.test']);
        $first = SignInProofs::of($user)->inSession('pending-1')->password();
        $owner = ProofOwner::of($user);

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($user, 'web', 'pending-1', $first, Requirement::none(), [PendingAction::VERIFY]),
        ));

        self::assertSame($first, $this->firstFactors()->forBinding($user, new ProofBinding($owner->type, $owner->key, 'web', 'pending-1', Purpose::SIGN_IN)));
        self::assertNull($this->firstFactors()->forBinding($user, new ProofBinding($owner->type, $owner->key, 'admin', 'pending-1', Purpose::SIGN_IN)));
    }

    /**
     * Sign a person in, with a sign-in the proof store knows.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function signIn(): TestUser
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'first-factor@example.test']);

        $this->actingAs($user);
        $this->store()->begin($user, 'web', SignInProofs::SESSION);

        return $user;
    }

    /**
     * The bound proof store.
     *
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): ProofStore
    {
        return $this->container()->make(ProofStore::class);
    }

    /**
     * The reader under test.
     *
     * @return \SineMacula\Laravel\Mfa\Context\SessionFirstFactor
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function firstFactors(): SessionFirstFactor
    {
        return $this->container()->make(SessionFirstFactor::class);
    }
}
