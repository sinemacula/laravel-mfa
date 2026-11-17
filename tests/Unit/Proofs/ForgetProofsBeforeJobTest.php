<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Queue\Jobs\FakeJob;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\ForgetProofsBeforeJob;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ForgetProofsBeforeJob::class)]
final class ForgetProofsBeforeJobTest extends TestCase
{
    /**
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * Every owner's sign-ins go; the rest of the session stays.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetsEveryProofBeforeAQueuedJob(): void
    {
        $session = $this->container()->make(Session::class);
        $store   = new SessionProofStore($session);
        $alice   = $this->user(7);
        $bob     = $this->user(8);

        $store->begin($alice, 'web', 'sign-in-1');
        $store->begin($bob, 'admin', 'sign-in-2');
        $session->put('mfa.other', 'kept');
        $session->put('cart', ['item']);

        (new ForgetProofsBeforeJob)(new JobProcessing('database', new FakeJob));

        self::assertNull($store->currentSession($alice, 'web'));
        self::assertNull($store->currentSession($bob, 'admin'));
        self::assertFalse($session->has(SessionProofStore::SESSION_KEY));
        self::assertSame('kept', $session->get('mfa.other'));
        self::assertSame(['item'], $session->get('cart'));
    }

    /**
     * A sync job runs inside the request that dispatched it, whatever its
     * connection is called.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testLeavesTheProofsOfASyncJob(): void
    {
        $store = new SessionProofStore($this->container()->make(Session::class));
        $user  = $this->user(7);

        $store->begin($user, 'web', 'sign-in-1');

        (new ForgetProofsBeforeJob)(new JobProcessing('inline', new SyncJob($this->container(), '{}', 'inline', 'default')));

        self::assertSame('sign-in-1', $store->currentSession($user, 'web'));
    }

    /**
     * @return void
     */
    public function testNeverStartsASession(): void
    {
        self::assertFalse($this->container()->resolved(Session::class));

        (new ForgetProofsBeforeJob)(new JobProcessing('database', new FakeJob));

        self::assertFalse($this->container()->resolved(Session::class));
    }

    /**
     * The key is the package's whatever store is bound, and the bound store is
     * never asked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetsTheProofsWithAnotherStoreBound(): void
    {
        $session = $this->container()->make(Session::class);

        $session->put(SessionProofStore::SESSION_KEY, ['4:user|7' => []]);
        $this->container()->instance(ProofStore::class, \Mockery::mock(ProofStore::class));

        (new ForgetProofsBeforeJob)(new JobProcessing('database', new FakeJob));

        self::assertFalse($session->has(SessionProofStore::SESSION_KEY));
    }

    /**
     * Under Octane the listener is registered once, at boot, and each job runs
     * in the current container.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testForgetsTheProofsOfTheCurrentContainer(): void
    {
        $boot    = $this->container()->make(Session::class);
        $current = new Store('worker', new ArraySessionHandler(10));
        $other   = new Container;

        $boot->put(SessionProofStore::SESSION_KEY, ['4:user|7' => []]);
        $current->put(SessionProofStore::SESSION_KEY, ['4:user|8' => []]);
        $other->instance(Session::class, $current);

        Container::setInstance($other);

        try {
            $this->container()->make(Dispatcher::class)->dispatch(new JobProcessing('database', new FakeJob));
        } finally {
            Container::setInstance($this->container());
        }

        self::assertFalse($current->has(SessionProofStore::SESSION_KEY));
        self::assertTrue($boot->has(SessionProofStore::SESSION_KEY));
    }

    /**
     * @param  int  $id
     * @return \Tests\Fixtures\Identities\TestUser
     */
    private function user(int $id): TestUser
    {
        $user = new TestUser;

        $user->setAttribute('id', $id);

        return $user;
    }
}
