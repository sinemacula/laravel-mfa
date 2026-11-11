<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

/**
 * A factor of the custom `my_driver` type, without persistence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MyDriverFactor extends AbstractFactorStub
{
    /**
     * @return mixed
     */
    #[\Override]
    public function getFactorIdentifier(): mixed
    {
        return 'x';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getType(): string
    {
        return 'my_driver';
    }
}
