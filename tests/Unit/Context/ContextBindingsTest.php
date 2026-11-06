<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Mfa\Context\ContextBindings;
use SineMacula\Laravel\Mfa\Context\IdentityContractActiveState;
use SineMacula\Laravel\Mfa\Context\IdentityContractSubjectType;
use SineMacula\Laravel\Mfa\Context\NoPendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\ActiveStateResolver;
use SineMacula\Laravel\Mfa\Contracts\PendingSessionResolver;
use SineMacula\Laravel\Mfa\Contracts\SubjectTypeResolver;
use Tests\TestCase;

/**
 * Tests for `ContextBindings`: no pending sessions and the identity contract's
 * subject type are the defaults, built afresh, and an application may rebind
 * either.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBindings::class)]
final class ContextBindingsTest extends TestCase
{
    /**
     * Rows of a seam and its default.
     *
     * @return iterable<string, array{class-string, class-string}>
     */
    public static function seams(): iterable
    {
        yield 'the pending session resolver' => [PendingSessionResolver::class, NoPendingSessionResolver::class];
        yield 'the subject type resolver' => [SubjectTypeResolver::class, IdentityContractSubjectType::class];
        yield 'the active state resolver' => [ActiveStateResolver::class, IdentityContractActiveState::class];
    }

    /**
     * Each seam is bound to its default, built afresh, and a binding of the
     * application's own replaces it.
     *
     * @param  class-string  $seam
     * @param  class-string  $default
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('seams')]
    public function testBindsEachSeamToItsDefault(string $seam, string $default): void
    {
        self::assertInstanceOf($default, $this->container()->make($seam));
        self::assertNotSame($this->container()->make($seam), $this->container()->make($seam));

        $own = \Mockery::mock($seam);

        $this->container()->instance($seam, $own);

        self::assertSame($own, $this->container()->make($seam));
    }
}
