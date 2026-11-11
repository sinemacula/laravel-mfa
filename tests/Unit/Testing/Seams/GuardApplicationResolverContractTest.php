<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing\Seams;

use Illuminate\Http\Request;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver;
use SineMacula\Laravel\Mfa\Testing\Seams\Concerns\GuardApplicationResolverTests;
use SineMacula\Laravel\Mfa\Testing\Seams\GuardApplicationResolverContract;
use Tests\Fixtures\Context\GuardPortalResolver;
use Tests\TestCase;

/**
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardApplicationResolverContract::class)]
final class GuardApplicationResolverContractTest extends TestCase
{
    use GuardApplicationResolverTests;

    /**
     * @return void
     */
    public function testRejectsAResolverThatNamesABlankApplicationThroughAGuard(): void
    {
        $resolver = new class implements GuardApplicationResolver {
            /**
             * @param  \Illuminate\Http\Request  $request
             * @return string
             */
            #[\Override]
            public function resolve(Request $request): string
            {
                return 'web';
            }

            /**
             * @param  \Illuminate\Http\Request  $request
             * @param  string  $guard
             * @return string
             */
            #[\Override]
            public function resolveForGuard(Request $request, string $guard): string
            {
                return ' ';
            }
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('The application of a request through a guard must not be blank.');

        GuardApplicationResolverContract::assertNamesOneApplicationThroughTheGuard($resolver, Request::create('/'), 'admin');
    }

    /**
     * Asked about the same request through a guard.
     *
     * @return void
     */
    public function testRejectsAResolverThatNamesAnotherApplicationEachTime(): void
    {
        $resolver = new class implements GuardApplicationResolver {
            /** @var int How many times it has been asked through a guard. */
            private int $asked = 0;

            /**
             * @param  \Illuminate\Http\Request  $request
             * @return string
             */
            #[\Override]
            public function resolve(Request $request): string
            {
                return 'web';
            }

            /**
             * @param  \Illuminate\Http\Request  $request
             * @param  string  $guard
             * @return string
             */
            #[\Override]
            public function resolveForGuard(Request $request, string $guard): string
            {
                return $guard . '-' . ++$this->asked;
            }
        };

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('A request must name the same application through a guard each time.');

        GuardApplicationResolverContract::assertNamesOneApplicationThroughTheGuard($resolver, Request::create('/'), 'admin');
    }

    /**
     * @return \SineMacula\Laravel\Mfa\Contracts\GuardApplicationResolver
     */
    #[\Override]
    protected function guardApplicationResolver(): GuardApplicationResolver
    {
        return new GuardPortalResolver;
    }

    /**
     * @return \Illuminate\Http\Request
     */
    #[\Override]
    protected function guardApplicationRequest(): Request
    {
        return Request::create('/');
    }

    /**
     * @return string
     */
    #[\Override]
    protected function applicationGuard(): string
    {
        return 'admin';
    }
}
