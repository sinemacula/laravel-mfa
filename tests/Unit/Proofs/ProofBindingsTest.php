<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\ProofStore;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\SessionProofStore;
use Tests\Fixtures\Identities\TestUser;
use Tests\TestCase;

/**
 * Tests for `ProofBindings`: the proof service is shared, the default proof
 * store keeps proofs in the session and is built afresh on every resolution,
 * and Laravel's sign-in and sign-out events begin and forget a sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofBindings::class)]
final class ProofBindingsTest extends TestCase
{
    /**
     * The proof service is a singleton.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRegistersTheServiceAsASingleton(): void
    {
        self::assertTrue($this->container()->isShared(ProofService::class));
        self::assertSame($this->container()->make(ProofService::class), $this->container()->make(ProofService::class));
    }

    /**
     * The default proof store keeps proofs in the session, and is not shared,
     * so no singleton holds one request's session into the next.
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
     * Laravel's `Login` event begins a sign-in, and `Logout` forgets it.
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

        self::assertNotNull($this->container()->make(ProofStore::class)->currentSession($user));

        $events->dispatch(new Logout('web', $user));

        self::assertNull($this->container()->make(ProofStore::class)->currentSession($user));
    }
}
