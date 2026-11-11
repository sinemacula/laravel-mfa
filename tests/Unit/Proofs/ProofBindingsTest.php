<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\PendingCompletion;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Contracts\StepUp;
use SineMacula\Laravel\Mfa\Proofs\GenerationSessionRevoker;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\ProofStoreCompletion;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofBindings::class)]
final class ProofBindingsTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBuildsTheServiceOnEveryResolution(): void
    {
        self::assertFalse($this->container()->isShared(ProofService::class));
        self::assertTrue($this->container()->bound(ProofService::class));
        self::assertNotSame($this->container()->make(ProofService::class), $this->container()->make(ProofService::class));
    }

    /**
     * Not shared, so nothing the container keeps holds one request's session
     * into the next.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheSessionStoreAfreshOnEveryResolution(): void
    {
        self::assertInstanceOf(SessionProofStore::class, $this->container()->make(ProofStore::class));
        self::assertFalse($this->container()->isShared(ProofStore::class));
        self::assertNotSame($this->container()->make(ProofStore::class), $this->container()->make(ProofStore::class));
    }

    /**
     * Both record in the proof store.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheDefaultCompletions(): void
    {
        self::assertInstanceOf(ProofStoreCompletion::class, $this->container()->make(PendingCompletion::class));
        self::assertInstanceOf(ProofStoreCompletion::class, $this->container()->make(StepUp::class));
    }

    /**
     * `Login` begins a sign-in; `Logout` and `CurrentDeviceLogout` forget it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testListensForSignInAndSignOut(): void
    {
        $events = $this->container()->make(Dispatcher::class);
        $user   = new TestUser;

        $user->setAttribute('id', 7);

        $events->dispatch(new Login('web', $user, false));

        self::assertNotNull($this->container()->make(ProofStore::class)->currentSession($user, 'web'));

        $events->dispatch(new Logout('web', $user));

        self::assertNull($this->container()->make(ProofStore::class)->currentSession($user, 'web'));

        $events->dispatch(new Login('web', $user, false));
        $events->dispatch(new CurrentDeviceLogout('web', $user));

        self::assertNull($this->container()->make(ProofStore::class)->currentSession($user, 'web'));
    }

    /**
     * Built afresh.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheGenerationRevokerByDefault(): void
    {
        self::assertInstanceOf(GenerationSessionRevoker::class, $this->container()->make(SessionRevoker::class));
        self::assertFalse($this->container()->isShared(SessionRevoker::class));
    }
}
