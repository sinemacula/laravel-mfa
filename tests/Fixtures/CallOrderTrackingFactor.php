<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Test-only `Factor` subclass that records the order of `issueCode()` and
 * `persist()` invocations against an externally-bound array reference, so the
 * abstract OTP driver tests can assert that dispatch happens before persistence
 * and that both sides fire.
 *
 * Lives in `tests/Fixtures` so it can be referenced by name (rather than
 * defined inline as an anonymous class) — that lets PHPStan read the docblock
 * on `bindTracker()`'s by-ref array parameter, which it cannot when the same
 * class is declared inside a trait method.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class CallOrderTrackingFactor extends Factor
{
    /** @var array<int, string> Externally-bound call-order tracker. */
    public array $tracker = [];

    /**
     * Bind the externally owned order tracker by reference so persistence-side
     * calls can be observed.
     *
     * @param  array<int, string>  $tracker
     * @return void
     */
    public function bindTracker(array &$tracker): void
    {
        $this->tracker = &$tracker;
    }

    /**
     * Record the call order before delegating to the parent implementation.
     *
     * @param  string  $code
     * @param  \Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    public function issueCode(#[\SensitiveParameter] string $code, CarbonInterface $expiresAt): void
    {
        $this->tracker[] = 'issueCode';
        parent::issueCode($code, $expiresAt);
    }

    /**
     * Record the call order before delegating to the parent implementation.
     *
     * @return void
     */
    public function persist(): void
    {
        $this->tracker[] = 'persist';
        parent::persist();
    }
}
