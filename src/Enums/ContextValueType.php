<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * The type of an `mfa` authentication context value when it is not null.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ContextValueType: string
{
    case BOOL = 'bool';

    // A list of strings
    case LIST   = 'list';
    case STRING = 'string';

    // An integer
    case NUMBER = 'number';
}
