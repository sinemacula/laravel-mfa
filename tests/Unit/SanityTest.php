<?php

declare(strict_types = 1);

namespace Tests\Unit;

use SineMacula\Laravel\Mfa\MfaManager;
use Tests\TestCase;

/**
 * Sanity check that the testbench bootstrap wires the package
 * service provider and exposes the MFA manager on the container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class SanityTest extends TestCase
{
    /**
     * The MFA manager should resolve from the container under the
     * `'mfa'` alias registered by the service provider.
     *
     * @return void
     */
    public function testManagerResolvesFromContainer(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
    }

    /**
     * The shipped default driver should be `'totp'` when no consumer
     * override is configured.
     *
     * @return void
     */
    public function testDefaultDriverIsTotp(): void
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager $manager */
        $manager = $this->container()->make('mfa');

        self::assertSame('totp', $manager->getDefaultDriver());
    }
}
