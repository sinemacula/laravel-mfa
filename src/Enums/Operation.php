<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Enums;

/**
 * The package's own named operations, each checked as step-up before the change
 * is made. Applications name their own in the same form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum Operation: string
{
    // Enrolling a further factor
    case ADD_FACTOR = 'mfa.add_factor';

    // Replacing a factor, such as rebinding its secret or destination
    case REPLACE_FACTOR = 'mfa.replace_factor';

    // Removing a factor
    case REMOVE_FACTOR = 'mfa.remove_factor';

    // Generating a new recovery code set
    case GENERATE_RECOVERY_CODES = 'mfa.generate_recovery_codes';

    /** @var string Dot-separated lower-case segments, each starting with a letter. */
    public const string NAME_PATTERN = '/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/D';

    /**
     * @param  string  $name
     * @return bool
     */
    public static function isName(string $name): bool
    {
        return preg_match(self::NAME_PATTERN, $name) === 1;
    }
}
