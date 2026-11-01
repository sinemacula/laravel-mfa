<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\MfaVerificationStore;
use SineMacula\Laravel\Mfa\Proofs\ProofBindings;
use SineMacula\Laravel\Mfa\Proofs\ProofService;
use SineMacula\Laravel\Mfa\Proofs\SessionMfaVerificationStore;
use Tests\TestCase;

/**
 * Tests for `ProofBindings`: the proof service is shared, and the default
 * verification store keeps verification in the session.
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
     * The default verification store keeps verification in the session, and is
     * shared.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheSessionStoreAsASingleton(): void
    {
        self::assertInstanceOf(SessionMfaVerificationStore::class, $this->container()->make(MfaVerificationStore::class));
        self::assertSame($this->container()->make(MfaVerificationStore::class), $this->container()->make(MfaVerificationStore::class));
    }
}
