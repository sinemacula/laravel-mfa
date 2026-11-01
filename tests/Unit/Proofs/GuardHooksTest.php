<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\GuardHooks;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;
use Tests\Unit\Concerns\BuildsProofs;

/**
 * Tests for `GuardHooks`: signing in begins a sign-in named by the first
 * factor's session and records the first factor, signing out forgets it, and a
 * first factor that would never count is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardHooks::class)]
final class GuardHooksTest extends TestCase
{
    use BuildsProofs, RefreshDatabase;

    /**
     * Signing in begins a sign-in named by the first factor's session and
     * records the first factor.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSignedInBeginsTheSignInAndRecordsTheFirstFactor(): void
    {
        $user  = $this->user();
        $proof = $this->firstFactor();

        GuardHooks::signedIn($user, $proof);

        self::assertSame('guard-session-1', $this->store()->currentSession($user));
        self::assertSame([$proof->toArray()], array_map(static fn (Proof $proof): array => $proof->toArray(), $this->store()->proofs($user, 'web')));
    }

    /**
     * Signing in again forgets everything the previous sign-in proved.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSignedInForgetsThePreviousSignIn(): void
    {
        $user = $this->user();

        GuardHooks::signedIn($user, $this->firstFactor());
        GuardHooks::signedIn($user, $this->firstFactor(7, 'guard-session-2'));

        self::assertSame('guard-session-2', $this->store()->currentSession($user));
        self::assertCount(1, $this->store()->proofs($user, 'web'));
    }

    /**
     * Signing out forgets the sign-in and every proof of it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSignedOutForgetsTheSignIn(): void
    {
        $user = $this->user();

        GuardHooks::signedIn($user, $this->firstFactor());
        GuardHooks::signedOut($user);

        self::assertNull($this->store()->currentSession($user));
        self::assertSame([], $this->store()->proofs($user, 'web'));
    }

    /**
     * A proof of anything but the first factor at sign-in is refused, and no
     * sign-in begins.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesAProofThatIsNotAFirstFactor(): void
    {
        $user = $this->user();

        try {
            GuardHooks::signedIn($user, self::proof(['binding' => new ProofBinding(TestUser::class, '7', 'web', 'guard-session-1', Purpose::STEP_UP), 'generation' => 0]));
            self::fail('Expected the additional factor proof to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('A guard signs an identity in with a proof of kind [first_factor], not [additional_factor].', $exception->getMessage());
        }

        self::assertNull($this->store()->currentSession($user));
    }

    /**
     * A first factor bound to another identity is refused.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefusesAFirstFactorOfAnotherIdentity(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The first factor\'s proof is bound to another identity.');

        GuardHooks::signedIn($this->user(), $this->firstFactor(8));
    }

    /**
     * A first factor made under another verification generation than the
     * identity's current one is refused, as it would never count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesAFirstFactorOfAnotherGeneration(): void
    {
        $user  = $this->user();
        $proof = $this->firstFactor();

        VerificationGeneration::advance($user);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The first factor\'s proof was not made under the identity\'s current verification generation.');

        GuardHooks::signedIn($user, $proof);
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
     * A test user with the given key, never saved.
     *
     * @param  int  $id
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(int $id = 7): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', $id);

        return $user;
    }

    /**
     * The proof of the password the test user with the given key signed in with
     * on the `web` application, at generation 0, bound to the guard's session.
     *
     * @param  int  $id
     * @param  string  $session
     * @return \SineMacula\Laravel\Mfa\Proofs\Proof
     */
    private function firstFactor(int $id = 7, string $session = 'guard-session-1'): Proof
    {
        return self::proof([
            'kind'       => ProofKind::FIRST_FACTOR,
            'method'     => 'password',
            'channel'    => new Channel(ChannelKind::PASSWORD),
            'reference'  => null,
            'provedAt'   => CarbonImmutable::now()->subSecond(),
            'binding'    => new ProofBinding(TestUser::class, (string) $id, 'web', $session, Purpose::SIGN_IN),
            'generation' => 0,
        ]);
    }
}
