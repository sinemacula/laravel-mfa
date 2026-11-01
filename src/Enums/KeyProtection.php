<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * How a credential's key was observed to be protected, reported as the `hwk` or
 * `swk` `amr` value only when it was observed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum KeyProtection: string
{
    // The key is held in hardware it cannot be exported from
    case HARDWARE = 'hardware';

    // The key is held in software
    case SOFTWARE = 'software';
}
