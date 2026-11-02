<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

/**
 * The form a factor's label is kept in: trimmed, a blank one being none, and no
 * longer than its column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorLabel
{
    /** @var int How many characters a label may hold. */
    public const int MAX_LENGTH = 255;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The label as it is kept, refusing one longer than a label may be: an
     * application validates what a person types before it gets here.
     *
     * @param  ?string  $label
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function normalize(?string $label): ?string
    {
        $trimmed = trim($label ?? '');

        if (mb_strlen($trimmed) > self::MAX_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A factor\'s label must not be longer than %d characters.', self::MAX_LENGTH));
        }

        return $trimmed === '' ? null : $trimmed;
    }
}
