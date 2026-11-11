<?php

declare(strict_types = 1);

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use SineMacula\Laravel\Mfa\MfaManager;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SanityTest extends TestCase
{
    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testManagerResolvesFromContainer(): void
    {
        $manager = $this->container()->make('mfa');

        self::assertInstanceOf(MfaManager::class, $manager);
    }

    /**
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testDefaultDriverIsTotp(): void
    {
        /** @var \SineMacula\Laravel\Mfa\MfaManager $manager */
        $manager = $this->container()->make('mfa');

        self::assertSame('totp', $manager->getDefaultDriver());
    }
}
