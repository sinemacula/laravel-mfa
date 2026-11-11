<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Throws a plain `RuntimeException` reading when it was disabled, which must
 * not be taken for an unreadable stored value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingReadFactor extends Factor
{
    /** @var string */
    public const string MESSAGE = 'The factor could not be read.';

    /**
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
