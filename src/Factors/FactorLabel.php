<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

/**
 * A factor's label, trimmed, blank as null, and no longer than its column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorLabel
{
    /** @var int In characters. */
    public const int MAX_LENGTH = 255;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Throws on a long label: the application validates input before this.
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
