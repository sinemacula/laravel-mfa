<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver;
use SineMacula\Laravel\Mfa\Assurance\Channel;
use SineMacula\Laravel\Mfa\Contracts\CombinationPolicy;
use SineMacula\Laravel\Mfa\Contracts\FreshnessGate;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Enums\ChannelKind;
use SineMacula\Laravel\Mfa\Enums\ProofKind;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Proofs\VerificationGeneration;
use SineMacula\Laravel\Mfa\Requirements\Requirement;
use Tests\Fixtures\Context\Callers;
use Tests\Fixtures\Identities\TestUser;
use Tests\Fixtures\Requirements\SignInProofs;
use Tests\TestCase;

/**
 * Tests for `DeclaredFirstFactorResolver`, the first factor without an
 * authentication layer: the application's declaration, for an identity with a
 * sign-in, dated at the epoch so it supplies no freshness of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeclaredFirstFactorResolver::class)]
final class DeclaredFirstFactorResolverTest extends TestCase
{
    /**
     * An application that declares no first factor has none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoDeclarationGivesNone(): void
    {
        config()->set('mfa.applications.web', ['types' => ['totp']]);

        self::assertNull($this->resolver()->resolve($this->signIn(), 'web'));
    }

    /**
     * An identity with no sign-in on the application has none.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoSignInGivesNone(): void
    {
        $this->declare('password', 'password');

        /** @var \Tests\Fixtures\Identities\TestUser $user */
        $user = TestUser::query()->create(['email' => 'signed-out@example.test']);

        self::assertNull($this->resolver()->resolve($user, 'web'));
    }

    /**
     * The declared first factor is a sign-in proof of the declared method and
     * channel kind, naming nothing and observing nothing, bound to the current
     * sign-in under the current generation and dated at the epoch.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Throwable
     */
    public function testTheDeclaredFirstFactor(): void
    {
        $this->declare('oidc', 'external_provider');

        $user = $this->signIn();

        VerificationGeneration::advance($user);

        $proof = $this->resolver()->resolve($user, 'web');

        self::assertNotNull($proof);
        self::assertSame(ProofKind::FIRST_FACTOR, $proof->kind);
        self::assertSame('oidc', $proof->method);
        self::assertEquals(new Channel(ChannelKind::EXTERNAL_PROVIDER), $proof->channel);
        self::assertNull($proof->reference);
        self::assertSame([], array_filter($proof->properties->toArray(), static fn (mixed $value): bool => $value !== null));
        self::assertSame(0, $proof->provedAt->getTimestamp());
        self::assertSame(Purpose::SIGN_IN, $proof->binding->purpose);
        self::assertSame(SignInProofs::SESSION, $proof->binding->sessionId);
        self::assertSame('web', $proof->binding->application);
        self::assertSame(1, $proof->generation);
    }

    /**
     * The freshness gate trusts the declared first factor, so a fresh further
     * factor after it is fresh; the first factor alone never is.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheGateTrustsItButItIsNeverFreshAlone(): void
    {
        $this->declare('password', 'password');

        $user        = $this->signIn();
        $requirement = Requirement::none()->withAdditionalVerification(900);

        self::assertFalse($this->container()->make(FreshnessGate::class)->isFresh(Callers::current(), 'billing.change_plan', $requirement));

        $this->container()->make(ProofStore::class)->record(SignInProofs::of($user)->totp(60));

        self::assertTrue($this->container()->make(FreshnessGate::class)->isFresh(Callers::current(), 'billing.change_plan', $requirement));

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(901));

        try {
            self::assertFalse($this->container()->make(FreshnessGate::class)->isFresh(Callers::current(), 'billing.change_plan', $requirement));
        } finally {
            CarbonImmutable::setTestNow();
        }
    }

    /**
     * A declared passkey first factor names no credential, so the combination
     * policy accepts no passkey after it: the credential that signed the person
     * in cannot be shown to differ.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testADeclaredPasskeyAcceptsNoFurtherPasskey(): void
    {
        $this->declare('passkey', 'passkey');

        $first  = $this->resolver()->resolve($this->signIn(), 'web');
        $policy = $this->container()->make(CombinationPolicy::class);

        self::assertNotNull($first);
        self::assertFalse($policy->accepts($first, new Channel(ChannelKind::PASSKEY, 'Y3JlZGVudGlhbC1vbmU')));
        self::assertTrue($policy->accepts($first, new Channel(ChannelKind::AUTHENTICATOR_APP, 'factor-totp')));
    }

    /**
     * Declare the application's first factor.
     *
     * @param  string  $method
     * @param  string  $channel
     * @return void
     */
    private function declare(string $method, string $channel): void
    {
        config()->set('mfa.applications.web', ['first_factor' => ['method' => $method, 'channel' => $channel]]);
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
        $user = TestUser::query()->create(['email' => 'declared@example.test']);

        $this->actingAs($user);
        $this->container()->make(ProofStore::class)->begin($user, 'web', SignInProofs::SESSION);

        return $user;
    }

    /**
     * The resolver under test.
     *
     * @return \SineMacula\Laravel\Mfa\Applications\DeclaredFirstFactorResolver
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function resolver(): DeclaredFirstFactorResolver
    {
        return $this->container()->make(DeclaredFirstFactorResolver::class);
    }
}
