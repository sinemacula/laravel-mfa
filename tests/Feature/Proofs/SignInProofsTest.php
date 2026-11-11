<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\FailureReason;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\EnsureMfaRequirementIsMet;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\GuardHooks;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Testing\AuthenticatorApp;
use SineMacula\Laravel\Mfa\Verification\Submission;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * The proofs a sign-in keeps, end to end through Laravel's auth events and the
 * guard hooks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofStore::class)]
#[CoversClass(GuardHooks::class)]
final class SignInProofsTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('mfa.applications.web', ['types' => ['totp'], 'first_factor' => ['method' => 'password', 'channel' => 'password']]);
    }

    /**
     * @return void
     */
    public function testAVerificationOnASignedInSessionRecordsItsProof(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->isVerified());

        $proofs = Mfa::proofs(Callers::current());

        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame('totp', $proofs[0]->method);
        self::assertSame($factor->getKey(), $proofs[0]->reference);
        self::assertSame(['kind' => 'authenticator_app', 'reference' => $factor->getKey()], $proofs[0]->channel?->toArray());
        self::assertSame('web', $proofs[0]->binding->application);
        self::assertSame(Purpose::STEP_UP, $proofs[0]->binding->purpose);
    }

    /**
     * @return void
     */
    public function testAVerificationsProofCarriesItsPurpose(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, $code), Purpose::SIGN_IN)->isVerified());

        $proofs = Mfa::proofs(Callers::current());

        self::assertCount(1, $proofs);
        self::assertSame(Purpose::SIGN_IN, $proofs[0]->binding->purpose);
    }

    /**
     * @return void
     */
    public function testSigningOutForgetsTheProofs(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        Auth::logout();
        Auth::setUser($user);

        self::assertSame([], Mfa::proofs(Callers::current()));
    }

    /**
     * @return void
     */
    public function testSigningOutOfTheCurrentDeviceForgetsTheProofs(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        self::assertCount(1, Mfa::proofs(Callers::current()));

        Auth::logoutCurrentDevice();
        Auth::setUser($user);

        self::assertSame([], Mfa::proofs(Callers::current()));
    }

    /**
     * Two session guards over one identity keep their own sign-ins.
     *
     * @return void
     */
    public function testSigningInToOrOutOfOneGuardLeavesAnotherAlone(): void
    {
        config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        Auth::guard('admin')->login($user);

        self::assertCount(1, Mfa::proofs(Callers::current()));

        Auth::guard('admin')->logout();

        self::assertCount(1, Mfa::proofs(Callers::current()));

        // An accepted TOTP step is never accepted again, so prove the next.
        self::assertTrue(Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, 1)))->isVerified());
        self::assertCount(2, Mfa::proofs(Callers::current()));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardCallingNeitherHookGainsNothingFromAnotherGuardsSignIn(): void
    {
        config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        Auth::guard('admin')->setUser($user);
        Auth::shouldUse('admin');

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Callers::current(), Submission::factor($factor->id, AuthenticatorApp::code($factor, 1)))->reason);

        $admin = Mfa::proofs(Callers::current());

        Auth::shouldUse('web');

        $web = Mfa::proofs(Callers::current());

        self::assertSame([], $admin);
        self::assertCount(1, $web);

        Auth::shouldUse('admin');

        $this->expectException(InsufficientAuthenticationException::class);

        $this->container()->make(EnsureMfaRequirementIsMet::class)->handle(
            $this->container()->make(Request::class),
            static fn (): Response => new Response('reached'),
        );
    }

    /**
     * The first identity signing in again starts with nothing either.
     *
     * @return void
     */
    public function testANewIdentityOnAReusedSessionInheritsNothing(): void
    {
        $alice = $this->createUser('alice@example.test');
        $bob   = $this->createUser('bob@example.test');

        Auth::login($alice);

        [$factor, $code] = $this->enrollTotp($alice);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        self::assertCount(1, Mfa::proofs(Callers::current()));

        Auth::login($bob);

        self::assertSame([], Mfa::proofs(Callers::current()));

        Auth::login($alice);

        self::assertSame([], Mfa::proofs(Callers::current()));
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAGuardCallingNeitherHookHasNoUsableProof(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::setUser($user);

        [$factor, $code] = $this->enrollTotp($user);

        self::assertSame(FailureReason::NOT_FOUND, Mfa::verify(Callers::current(), Submission::factor($factor->id, $code))->reason);
        self::assertSame([], Mfa::proofs(Callers::current()));

        $this->expectException(InsufficientAuthenticationException::class);

        $this->container()->make(EnsureMfaRequirementIsMet::class)->handle(
            $this->container()->make(Request::class),
            static fn (): Response => new Response('reached'),
        );
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testACustomGuardsHooksKeepItsProofs(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::setUser($user);

        GuardHooks::signedIn($user, new Proof(
            ProofKind::FIRST_FACTOR,
            'password',
            new Channel(ChannelKind::PASSWORD),
            null,
            ObservedProperties::none(),
            CarbonImmutable::now(),
            new ProofBinding(TestUser::class, (string) $user->id, 'web', 'guard-session-1', Purpose::SIGN_IN),
            VerificationGeneration::current($user),
        ));

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify(Callers::current(), Submission::factor($factor->id, $code));

        $proofs = Mfa::proofs(Callers::current());

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR], array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs));
        self::assertSame('guard-session-1', $proofs[1]->binding->sessionId);

        GuardHooks::signedOut($user, 'web');

        self::assertSame([], Mfa::proofs(Callers::current()));
    }

    /**
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGenerationBumpInvalidatesOtherSessions(): void
    {
        $user    = $this->createUser('alice@example.test');
        $phone   = new SessionProofStore(new Store('phone', new ArraySessionHandler(10)));
        $laptop  = new SessionProofStore(new Store('laptop', new ArraySessionHandler(10)));
        $proveOn = static function (SessionProofStore $store, string $session, int $generation) use ($user): void {
            $store->record($user, new Proof(
                ProofKind::ADDITIONAL_FACTOR,
                'totp',
                new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-1'),
                'factor-1',
                ObservedProperties::none(),
                CarbonImmutable::now(),
                new ProofBinding(TestUser::class, (string) $user->id, 'web', $session, Purpose::STEP_UP),
                $generation,
            ));
        };

        $phone->begin($user, 'web', 'phone-sign-in');
        $laptop->begin($user, 'web', 'laptop-sign-in');
        $proveOn($phone, 'phone-sign-in', 0);
        $proveOn($laptop, 'laptop-sign-in', 0);

        VerificationGeneration::advance($user);

        self::assertSame([], $phone->proofs($user, 'web', 'phone-sign-in'));
        self::assertSame([], $laptop->proofs($user, 'web', 'laptop-sign-in'));

        $proveOn($laptop, 'laptop-sign-in', 1);

        self::assertSame([], $phone->proofs($user, 'web', 'phone-sign-in'));
        self::assertCount(1, $laptop->proofs($user, 'web', 'laptop-sign-in'));
    }

    /**
     * @param  string  $email
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function createUser(string $email): TestUser
    {
        return TestUser::create([
            'email'       => $email,
            'mfa_enabled' => true,
        ]);
    }

    /**
     * A confirmed TOTP factor and its current code.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor, 1: string}
     */
    private function enrollTotp(TestUser $user): array
    {
        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            ...AuthenticatorApp::FACTOR,
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'status'               => 'confirmed',
        ]);

        return [$factor, AuthenticatorApp::code($factor)];
    }
}
