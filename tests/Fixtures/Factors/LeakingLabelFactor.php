<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * Fails to read its label with the destination in the message and in a helper's
 * arguments, as a careless application model might.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LeakingLabelFactor extends Factor
{
    /**
     * @return ?string
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function getLabel(): ?string
    {
        return self::refuse((string) $this->getDestination());
    }

    /**
     * @param  string  $destination
     * @return never
     *
     * @throws \RuntimeException
     */
    private static function refuse(string $destination): never
    {
        throw new \RuntimeException(sprintf('No label could be read for %s.', $destination));
    }
}
