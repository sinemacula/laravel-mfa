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
use PragmaRX\Google2FA\Google2FA;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Exceptions\MfaRequiredException;
use SineMacula\Laravel\Mfa\Facades\Mfa;
use SineMacula\Laravel\Mfa\Http\Middleware\RequireMfa;
use SineMacula\Laravel\Mfa\Models\Factor;
use SineMacula\Laravel\Mfa\Proofs\GuardHooks;
use SineMacula\Laravel\Mfa\Proofs\Proof;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * End-to-end tests of the proofs a sign-in keeps: a verification on a signed-in
 * session records its proof, Laravel's sign-in and sign-out events clear what
 * the session held so a new identity on a reused session inherits nothing, each
 * guard's application keeps its own sign-in, a guard that fires neither event
 * nor calls the hooks has no usable proof, a custom guard's hooks record its
 * first factor, and advancing the identity's verification generation
 * invalidates its other sessions.
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
     * A TOTP verification on a signed-in session records an additional factor
     * proof of the factor on the default guard's application.
     *
     * @return void
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testAVerificationOnASignedInSessionRecordsItsProof(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $proofs = Mfa::proofs();

        self::assertCount(1, $proofs);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, $proofs[0]->kind);
        self::assertSame('totp', $proofs[0]->method);
        self::assertSame($factor->getKey(), $proofs[0]->reference);
        self::assertSame(['kind' => 'authenticator_app', 'reference' => $factor->getKey()], $proofs[0]->channel?->toArray());
        self::assertSame('web', $proofs[0]->binding->application);
        self::assertSame(Purpose::STEP_UP, $proofs[0]->binding->purpose);
    }

    /**
     * Signing out forgets every proof of the sign-in.
     *
     * @return void
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testSigningOutForgetsTheProofs(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify('totp', $factor, $code);

        Auth::logout();
        Auth::setUser($user);

        self::assertSame([], Mfa::proofs());
    }

    /**
     * Signing out of the current device forgets every proof of the sign-in, as
     * signing out does.
     *
     * @return void
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testSigningOutOfTheCurrentDeviceForgetsTheProofs(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify('totp', $factor, $code);

        self::assertCount(1, Mfa::proofs());

        Auth::logoutCurrentDevice();
        Auth::setUser($user);

        self::assertSame([], Mfa::proofs());
    }

    /**
     * Two session guards over the same identity keep their own sign-ins:
     * signing in to or out of one leaves the other's sign-in and proofs alone,
     * and the other still records what it proves.
     *
     * @return void
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testSigningInToOrOutOfOneGuardLeavesAnotherAlone(): void
    {
        config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify('totp', $factor, $code);

        Auth::guard('admin')->login($user);

        self::assertCount(1, Mfa::proofs());

        Auth::guard('admin')->logout();

        self::assertCount(1, Mfa::proofs());

        $factor->refresh();

        self::assertTrue(Mfa::verify('totp', $factor, $code));
        self::assertCount(2, Mfa::proofs());
    }

    /**
     * A guard that fires neither event nor calls the hooks gains nothing from
     * the identity's sign-in through another guard: its verification records
     * nothing, it has no proofs, and the other guard's are untouched.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testAGuardCallingNeitherHookGainsNothingFromAnotherGuardsSignIn(): void
    {
        config()->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'users']);

        $user = $this->createUser('alice@example.test');

        Auth::login($user);

        [$factor, $code] = $this->enrollTotp($user);

        Mfa::verify('totp', $factor, $code);

        Auth::guard('admin')->setUser($user);
        Auth::shouldUse('admin');

        $factor->refresh();

        self::assertTrue(Mfa::verify('totp', $factor, $code));

        $admin = Mfa::proofs();

        Auth::shouldUse('web');

        $web = Mfa::proofs();

        self::assertSame([], $admin);
        self::assertCount(1, $web);

        Auth::shouldUse('admin');

        $this->expectException(MfaRequiredException::class);

        $this->container()->make(RequireMfa::class)->handle(
            $this->container()->make(Request::class),
            static fn (): Response => new Response('reached'),
        );
    }

    /**
     * Another identity signing in on a reused session inherits nothing, and the
     * first identity signing in again starts with nothing either.
     *
     * @return void
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testANewIdentityOnAReusedSessionInheritsNothing(): void
    {
        $alice = $this->createUser('alice@example.test');
        $bob   = $this->createUser('bob@example.test');

        Auth::login($alice);

        [$factor, $code] = $this->enrollTotp($alice);

        Mfa::verify('totp', $factor, $code);

        self::assertCount(1, Mfa::proofs());

        Auth::login($bob);

        self::assertSame([], Mfa::proofs());

        Auth::login($alice);

        self::assertSame([], Mfa::proofs());
    }

    /**
     * A guard that fires neither of Laravel's events nor calls the hooks leaves
     * no sign-in: a successful verification records nothing, and the middleware
     * still requires one.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    public function testAGuardCallingNeitherHookHasNoUsableProof(): void
    {
        $user = $this->createUser('alice@example.test');

        Auth::setUser($user);

        [$factor, $code] = $this->enrollTotp($user);

        self::assertTrue(Mfa::verify('totp', $factor, $code));
        self::assertSame([], Mfa::proofs());

        $this->expectException(MfaRequiredException::class);

        $this->container()->make(RequireMfa::class)->handle(
            $this->container()->make(Request::class),
            static fn (): Response => new Response('reached'),
        );
    }

    /**
     * A custom guard's hooks begin a sign-in that records the first factor and
     * keeps the proofs that follow, and signing out forgets them.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
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

        Mfa::verify('totp', $factor, $code);

        $proofs = Mfa::proofs();

        self::assertSame([ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR], array_map(static fn (Proof $proof): ProofKind => $proof->kind, $proofs));
        self::assertSame('guard-session-1', $proofs[1]->binding->sessionId);

        GuardHooks::signedOut($user, 'web');

        self::assertSame([], Mfa::proofs());
    }

    /**
     * Advancing the identity's verification generation invalidates the proofs
     * of every session, not only the current one, and a proof made afterwards
     * counts again.
     *
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
            $store->record(new Proof(
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

        self::assertSame([], $phone->proofs($user, 'web'));
        self::assertSame([], $laptop->proofs($user, 'web'));

        $proveOn($laptop, 'laptop-sign-in', 1);

        self::assertSame([], $phone->proofs($user, 'web'));
        self::assertCount(1, $laptop->proofs($user, 'web'));
    }

    /**
     * Persist a test user who opts into MFA.
     *
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
     * Enrol a TOTP factor for the user, returning it and its current code.
     *
     * @param  \Tests\Fixtures\Identities\TestUser  $user
     * @return array{0: \SineMacula\Laravel\Mfa\Models\Factor, 1: string}
     *
     * @throws \PragmaRX\Google2FA\Exceptions\IncompatibleWithGoogleAuthenticatorException
     * @throws \PragmaRX\Google2FA\Exceptions\InvalidCharactersException
     * @throws \PragmaRX\Google2FA\Exceptions\SecretKeyTooShortException
     */
    private function enrollTotp(TestUser $user): array
    {
        $google = new Google2FA;
        $secret = $google->generateSecretKey();

        /** @var \SineMacula\Laravel\Mfa\Models\Factor $factor */
        $factor = Factor::create([
            'authenticatable_type' => $user::class,
            'authenticatable_id'   => (string) $user->id,
            'type'                 => 'totp',
            'secret'               => $secret,
        ]);

        return [$factor, $google->getCurrentOtp($secret)];
    }
}
