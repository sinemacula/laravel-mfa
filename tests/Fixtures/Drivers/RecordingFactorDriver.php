<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers;

use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\FactorDriver;
use Tests\Fixtures\Drivers\Concerns\DescribesNoChannel;

/**
 * Custom `FactorDriver` fixture that records issue / verify calls and accepts
 * `'correct'` as the only valid code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingFactorDriver implements FactorDriver
{
    use DescribesNoChannel;

    /** @var int Issuance call counter for the test assertions. */
    public int $issueCalls = 0;

    /** @var int Verify call counter for the test assertions. */
    public int $verifyCalls = 0;

    /**
     * Record the issuance call without performing any work.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @return void
     */
    #[\Override]
    public function issueChallenge(Factor $factor): void
    {
        $this->issueCalls++;
    }

    /**
     * Record the verify call and report success only when the submitted code is
     * the magic string `'correct'`.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  string  $code
     * @return bool
     */
    #[\Override]
    public function verify(Factor $factor, #[\SensitiveParameter] string $code): bool
    {
        $this->verifyCalls++;

        return $code === 'correct';
    }
}
