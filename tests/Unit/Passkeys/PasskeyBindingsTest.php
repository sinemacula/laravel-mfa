<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Contracts\PasskeyGateway;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssertions;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociations;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyBindings;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\UnavailablePasskeyGateway;
use Tests\Fixtures\Passkeys\FakePasskeyGateway;
use Tests\TestCase;

/**
 * Tests for `PasskeyBindings`: passkeys are unavailable by default, an
 * application may bind its own gateway, and the change gate, the assertions and
 * the association records are built afresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyBindings::class)]
final class PasskeyBindingsTest extends TestCase
{
    /**
     * The gateway defaults to the unavailable one, built afresh, and a binding
     * of the application's own replaces it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBindsTheUnavailableGatewayByDefault(): void
    {
        self::assertInstanceOf(UnavailablePasskeyGateway::class, $this->container()->make(PasskeyGateway::class));
        self::assertFalse($this->container()->isShared(PasskeyGateway::class));

        $own = new FakePasskeyGateway;

        $this->container()->instance(PasskeyGateway::class, $own);

        self::assertSame($own, $this->container()->make(PasskeyGateway::class));
    }

    /**
     * Rows of a service the bindings build afresh.
     *
     * @return iterable<string, array{class-string}>
     */
    public static function services(): iterable
    {
        yield 'the change gate' => [PasskeyChangeGate::class];
        yield 'the assertions' => [PasskeyAssertions::class];
        yield 'the association records' => [PasskeyAssociations::class];
    }

    /**
     * Each service is built afresh.
     *
     * @param  class-string  $service
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('services')]
    public function testBuildsTheServiceOnEveryResolution(string $service): void
    {
        self::assertFalse($this->container()->isShared($service));
        self::assertTrue($this->container()->bound($service));
        self::assertNotSame($this->container()->make($service), $this->container()->make($service));
    }
}
