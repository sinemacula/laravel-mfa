<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Drivers\AbstractOtpDriver;

/**
 * Test-only `AbstractOtpDriver` shape that records every `dispatch()`
 * call against an externally observable list and tracks the dispatch /
 * persist call order through a shared array reference.
 *
 * Lives in `tests/Fixtures` so the unit-test driver factory can lock a
 * concrete return type without resorting to inline `object{...}` types
 * — which exceed PHPDoc line-length limits and trip Slevomat's FQN
 * rule when expressed via `@phpstan-type` aliases.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class DispatchTrackingOtpDriver extends AbstractOtpDriver
{
    /** @var list<array{factor: \SineMacula\Laravel\Mfa\Contracts\EloquentFactor, code: string}> */
    public array $dispatched = [];

    /** @var array<int, string> */
    public array $order = [];

    /**
     * Bind the order-tracker to an external array reference so test
     * assertions can observe call ordering without touching the driver.
     *
     * @param  array<int, string>  $tracker
     * @return void
     */
    public function bindOrderRef(array &$tracker): void
    {
        $this->order = &$tracker;
    }

    /**
     * Required by the parent contract; concrete tests provide their own
     * dispatch behaviour through anonymous subclasses.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\EloquentFactor  $factor
     * @param  string  $code
     * @return void
     */
    abstract protected function dispatch(
        EloquentFactor $factor,
        #[\SensitiveParameter]
        string $code,
    ): void;
}
