<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Logout;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException;
use SineMacula\Laravel\Mfa\Proofs\ForgetSignInOnLogout;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Identities\NonScalarIdentifierUser;
use Tests\Fixtures\Identities\PlainUser;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `ForgetSignInOnLogout`: Laravel's `Logout` and
 * `CurrentDeviceLogout` events forget the identity's sign-in on the application
 * their guard acts for, leave its sign-in on another alone, and leave an
 * identity that holds none alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetSignInOnLogout::class)]
final class ForgetSignInOnLogoutTest extends TestCase
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
     * Signing out forgets the identity's sign-in on the guard's application and
     * leaves its sign-in on another alone.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetsTheSignInOnTheGuardsApplication(): void
    {
        $store = $this->bindStore(new SessionProofStore(new Store('test', new ArraySessionHandler(10))));
        $user  = $this->user();

        $store->begin($user, 'web', 'sign-in-1');
        $store->begin($user, 'admin', 'sign-in-2');

        $this->listener()(new Logout('web', $user));

        self::assertNull($store->currentSession($user, 'web'));
        self::assertSame('sign-in-2', $store->currentSession($user, 'admin'));
    }

    /**
     * Signing out of the current device forgets the identity's sign-in too.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetsTheSignInOnCurrentDeviceLogout(): void
    {
        $store = $this->bindStore(new SessionProofStore(new Store('test', new ArraySessionHandler(10))));
        $user  = $this->user();

        $store->begin($user, 'web', 'sign-in-1');

        $this->listener()(new CurrentDeviceLogout('web', $user));

        self::assertNull($store->currentSession($user, 'web'));
    }

    /**
     * An identity that cannot hold factors forgets nothing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesAnIdentityThatCannotHoldFactorsAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldNotReceive('forget');

        $this->bindStore($store);

        $this->listener()(new Logout('web', new PlainUser));

        $store->shouldNotHaveReceived('forget');

        $this->addToAssertionCount(1);
    }

    /**
     * An identity whose key cannot name a record signs out without failing.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesAnIdentityWhoseKeyCannotNameARecordAlone(): void
    {
        $store = \Mockery::mock(ProofStore::class);
        $store->shouldReceive('forget')->once()->andThrow(new UnsupportedIdentifierException('Unsupported.'));

        $this->bindStore($store);

        $this->listener()(new Logout('web', new NonScalarIdentifierUser));

        $store->shouldHaveReceived('forget')->once();

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
     * @return \SineMacula\Laravel\Mfa\Proofs\ForgetSignInOnLogout
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function listener(): ForgetSignInOnLogout
    {
        return new ForgetSignInOnLogout($this->container()->make(ProofService::class));
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
