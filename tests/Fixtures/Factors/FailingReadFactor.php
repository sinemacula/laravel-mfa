<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model whose state cannot be read for a reason that has nothing to do
 * with what is stored: reading when it was disabled throws a plain
 * `RuntimeException`, as an application's own model might when something it
 * relies on fails. Nothing may take that for a factor that cannot be read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingReadFactor extends Factor
{
    /** @var string The message the read fails with. */
    public const string MESSAGE = 'The factor could not be read.';

    /**
     * Fail to read when the factor was disabled.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function getDisabledAt(): ?CarbonInterface
    {
        throw new \RuntimeException(self::MESSAGE);
    }
}
