<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

/**
 * Minimal `Factor` fixture reporting against the `my_driver` name — feeds the
 * custom-driver dispatch path without touching persistence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class MyDriverFactor extends AbstractFactorStub
{
    /**
     * Return the fixture's fixed factor identifier.
     *
     * @return mixed
     */
    public function getFactorIdentifier(): mixed
    {
        return 'x';
    }

    /**
     * Return the fixture's custom driver name.
     *
     * @return string
     */
    public function getDriver(): string
    {
        return 'my_driver';
    }
}
