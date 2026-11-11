<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use Carbon\CarbonImmutable;
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
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Context\FixedPendingSessionResolver;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\FixedFirstFactorResolver;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionFirstFactor::class)]
final class SessionFirstFactorTest extends TestCase
{
    /**
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

        $this->store()->record($user, $proofs->password(60));
        $this->store()->record($user, $latest);
        $this->store()->record($user, $proofs->totp());

        self::assertEquals($latest, $this->firstFactors()->current($user, 'web'));
        self::assertCount(3, $this->firstFactors()->proofs($user, 'web'));
        self::assertSame(0, $resolver->asked);
    }

    /**
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
        $this->store()->record($user, $proofs->totp());

        self::assertEquals($first, $this->firstFactors()->current($user, 'web'));
        self::assertSame(
            [ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR],
            array_map(static fn (Proof $proof): ProofKind => $proof->kind, $this->firstFactors()->proofs($user, 'web')),
        );
    }

    /**
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
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABindingOfTheCurrentSignInHasItsFirstFactor(): void
    {
        $user  = $this->signIn();
        $first = SignInProofs::of($user)->password();
        $owner = ProofOwner::of($user);

        $this->store()->record($user, $first);

        $found = $this->firstFactors()->forBinding($user, new ProofBinding($owner->type, $owner->key, 'web', SignInProofs::SESSION, Purpose::STEP_UP), Callers::current()->pending);

        self::assertSame($first->toArray(), $found?->toArray());
        $binding = new ProofBinding($owner->type, $owner->key, 'web', 'elsewhere', Purpose::STEP_UP);

        self::assertNull($this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
        $binding = new ProofBinding($owner->type, 'someone-else', 'web', SignInProofs::SESSION, Purpose::STEP_UP);

        self::assertNull($this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
    }

    /**
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
            new PendingContext($user, 'web', 'pending-1', $first, Requirement::none(), [PendingAction::VERIFY], CarbonImmutable::now()->addHour()),
        ));

        $binding = new ProofBinding($owner->type, $owner->key, 'web', 'pending-1', Purpose::SIGN_IN);

        self::assertSame($first, $this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
        $binding = new ProofBinding($owner->type, $owner->key, 'admin', 'pending-1', Purpose::SIGN_IN);

        self::assertNull($this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
    }

    /**
     * Only under the identity's current verification generation and when not
     * dated in the future.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPendingFirstFactorMustStillCount(): void
    {
        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user   = TestUser::query()->create(['email' => 'stale@example.test']);
        $proofs = SignInProofs::of($user)->inSession('pending-1');
        $owner  = ProofOwner::of($user);

        $pending = static fn (Proof $first): PendingContext => new PendingContext(
            $user,
            'web',
            'pending-1',
            $first,
            Requirement::none(),
            [PendingAction::VERIFY],
            CarbonImmutable::now()->addHour(),
        );

        $current = $pending($proofs->password());
        $future  = $pending($proofs->password(-300));

        self::assertSame($current->firstFactor, $this->firstFactors()->ofPending($user, $current));
        self::assertNull($this->firstFactors()->ofPending($user, $future));

        VerificationGeneration::advance($user);

        self::assertNull($this->firstFactors()->ofPending($user, $current));

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver($current));

        $binding = new ProofBinding($owner->type, $owner->key, 'web', 'pending-1', Purpose::SIGN_IN);

        self::assertNull($this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAPendingSessionNeverReachesAnActiveSignIn(): void
    {
        $user  = $this->signIn();
        $owner = ProofOwner::of($user);

        $this->store()->record($user, SignInProofs::of($user)->password());

        $first = SignInProofs::of($user)->onApplication('admin')->inSession('pending-1')->password();

        $this->container()->instance(PendingSessionResolver::class, new FixedPendingSessionResolver(
            new PendingContext($user, 'admin', 'pending-1', $first, Requirement::none(), [PendingAction::VERIFY], CarbonImmutable::now()->addHour()),
        ));

        $binding = new ProofBinding($owner->type, $owner->key, 'web', SignInProofs::SESSION, Purpose::STEP_UP);

        self::assertNull($this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAReplacedSignInLendsNoProofs(): void
    {
        $user = $this->signIn();

        $this->store()->record($user, SignInProofs::of($user)->password(60));
        $this->store()->record($user, SignInProofs::of($user)->totp());

        $this->store()->begin($user, 'web', 'sign-in-2');
        $this->store()->record($user, SignInProofs::of($user)->inSession('sign-in-2')->password());

        self::assertSame([], $this->firstFactors()->proofsOf($user, 'web', SignInProofs::SESSION));
        self::assertCount(1, $this->firstFactors()->proofsOf($user, 'web', 'sign-in-2'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheResolvedFirstFactorMustBeOfTheNamedSignIn(): void
    {
        $user  = $this->signIn();
        $first = SignInProofs::of($user)->inSession('sign-in-2')->password(60);

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver($first));

        $this->store()->begin($user, 'web', 'sign-in-2');

        self::assertSame([], $this->firstFactors()->proofsOf($user, 'web', SignInProofs::SESSION));
        self::assertEquals([$first], $this->firstFactors()->proofsOf($user, 'web', 'sign-in-2'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAResolverAnsweringAReplacedSignInLendsItNothing(): void
    {
        $user  = $this->signIn();
        $stale = SignInProofs::of($user)->password(60);

        $this->container()->instance(FirstFactorResolver::class, new FixedFirstFactorResolver($stale));

        self::assertEquals([$stale], $this->firstFactors()->proofsOf($user, 'web', SignInProofs::SESSION));

        $this->store()->begin($user, 'web', 'sign-in-2');

        self::assertSame([], $this->firstFactors()->proofsOf($user, 'web', SignInProofs::SESSION));
        self::assertNull($this->firstFactors()->current($user, 'web'));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testABindingOfAReplacedSignInHasNoFirstFactor(): void
    {
        $user  = $this->signIn();
        $owner = ProofOwner::of($user);

        $this->store()->record($user, SignInProofs::of($user)->password());
        $this->store()->begin($user, 'web', 'sign-in-2');
        $this->store()->record($user, SignInProofs::of($user)->inSession('sign-in-2')->password());

        $binding = new ProofBinding($owner->type, $owner->key, 'web', SignInProofs::SESSION, Purpose::STEP_UP);

        self::assertNull($this->firstFactors()->forBinding($user, $binding, $this->pendingOfTheRequest()));
    }

    /**
     * With a sign-in the proof store knows.
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
     * @return \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function store(): ProofStore
    {
        return $this->container()->make(ProofStore::class);
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Context\SessionFirstFactor
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function firstFactors(): SessionFirstFactor
    {
        return $this->container()->make(SessionFirstFactor::class);
    }

    /**
     * @return ?\SineMacula\Laravel\Mfa\Context\PendingContext
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function pendingOfTheRequest(): ?PendingContext
    {
        return Callers::current()->pending;
    }
}
