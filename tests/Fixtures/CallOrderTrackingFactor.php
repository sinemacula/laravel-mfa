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
 * defined inline as an anonymous class) — that lets PHPStan read the typed
 * `$tracker` property, which callers bind by reference from the outside so the
 * model itself carries no behavior beyond the recording overrides.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CallOrderTrackingFactor extends Factor
{
    /** @var array<int, string> Externally-bound call-order tracker. */
    public array $tracker = [];

    /**
     * Record the call order before delegating to the parent implementation.
     *
     * @param  string  $code
     * @param  \Carbon\CarbonInterface  $expiresAt
     * @return void
     */
    #[\Override]
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
    #[\Override]
    public function persist(): void
    {
        $this->tracker[] = 'persist';
        parent::persist();
    }
}
