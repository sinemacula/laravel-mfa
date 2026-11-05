<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Mfa\Models\Factor;

/**
 * A factor model whose label cannot be read, failing with its own destination
 * in the message and in a helper's arguments, as a careless application model
 * might: the code service reads the label while it builds a code's message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LeakingLabelFactor extends Factor
{
    /**
     * Fail to read the label, quoting the destination.
     *
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
     * Refuse, quoting the destination given.
     *
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
