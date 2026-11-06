<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Auth\Events\Login;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ApplicationResolver;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\BeginSignInOnLogin;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Context\GuardPortalResolver;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `BeginSignInOnLogin`: Laravel's `Login` event begins a new sign-in,
 * named by a fresh random id, on the application its guard acts for, for an
 * identity that can hold factors, and leaves every other identity alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BeginSignInOnLogin::class)]
final class BeginSignInOnLoginTest extends TestCase
{
    /**
     * Tear down Mockery expectations between test cases.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * Every sign-in begins under a fresh lowercase ULID.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBeginsASignInUnderAFreshId(): void
    {
        $store    = $this->bindStore(new SessionProofStore(new Store('test', new ArraySessionHandler(10))));
        $listener = $this->listener();
        $user     = $this->user();

        $listener(new Login('web', $user, false));

        $first = $store->currentSession($user, 'web');

        $listener(new Login('web', $user, false));

        $second = $store->currentSession($user, 'web');

        self::assertIsString($first);
        self::assertIsString($second);
        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $first);
        self::assertNotSame($first, $second);
    }

    /**
     * The sign-in begins on the application the event's guard acts for, and
     * leaves the identity's sign-in on another alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBeginsTheSignInOnTheGuardsApplication(): void
    {
        $store = $this->bindStore(new SessionProofStore(new Store('test', new ArraySessionHandler(10))));
        $user  = $this->user();

        $store->begin($user, 'web', 'sign-in-1');

        $this->listener()(new Login('admin', $user, false));

        self::assertSame('sign-in-1', $store->currentSession($user, 'web'));
        self::assertIsString($store->currentSession($user, 'admin'));
    }

    /**
     * With a guard application resolver bound, the sign-in begins on the
     * application it names through the event's guard, not the one it names
     * without it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBeginsTheSignInOnTheApplicationNamedThroughTheGuard(): void
    {
        $store = $this->bindStore(new SessionProofStore(new Store('test', new ArraySessionHandler(10))));
        $user  = $this->user();

        $this->container()->instance(ApplicationResolver::class, new GuardPortalResolver);

        $this->listener()(new Login('admin', $user, false));

        self::assertIsString($store->currentSession($user, 'admin-portal'));
        self::assertNull($store->currentSession($user, 'web-portal'));
    }

    /**
     * An identity that cannot hold factors begins no sign-in.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesAnIdentityThatCannotHoldFactorsAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldNotReceive('begin');

        $this->bindStore($store);

        $this->listener()(new Login('web', new PlainUser, false));

        $store->shouldNotHaveReceived('begin');

        $this->addToAssertionCount(1);
    }

    /**
     * An identity whose key cannot name a record signs in without a sign-in of
     * its own rather than failing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesAnIdentityWhoseKeyCannotNameARecordAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('begin')->once()->andThrow(new UnsupportedIdentifierException('Unsupported.'));

        $this->bindStore($store);

        $this->listener()(new Login('web', new NonScalarIdentifierUser, false));

        $store->shouldHaveReceived('begin')->once();

        $this->addToAssertionCount(1);
    }

    /**
     * Bind the store the listener's proof service reaches.
     *
     * @template TStore of \SineMacula\Laravel\Mfa\Contracts\ProofStore
     *
     * @param  TStore  $store
     * @return TStore
     */
    private function bindStore(ProofStore $store): ProofStore
    {
        $this->container()->instance(ProofStore::class, $store);

        return $store;
    }

    /**
     * The listener under test.
     *
     * @return \SineMacula\Laravel\Mfa\Proofs\BeginSignInOnLogin
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function listener(): BeginSignInOnLogin
    {
        return new BeginSignInOnLogin($this->container()->make(ProofService::class));
    }

    /**
     * A test user, never saved.
     *
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', 7);

        return $user;
    }
}
