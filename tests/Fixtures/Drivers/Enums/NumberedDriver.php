<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Drivers\Enums;

/**
 * An integer-backed enum, whose cases name drivers by their values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum NumberedDriver: int
{
    case FIRST = 1;
}
