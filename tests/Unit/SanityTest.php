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
    public function testManagerResolvesFromContainer(): void
    {
        $manager = $this->app->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
    }

    public function testDefaultDriverIsTotp(): void
    {
        /** @var MfaManager $manager */
        $manager = $this->app->make('mfa');

        self::assertSame('totp', $manager->getDefaultDriver());
    }
}
