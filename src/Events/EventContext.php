<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * The allowlist of every event's context. A bound resolver may return anything,
 * so values are cut to these keys and to integers and strings.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EventContext
{
    /** @var list<string> */
    public const array KEYS = [
        'identity_type',
        'identity_id',
        'principal_type',
        'principal_id',
        'tenant_id',
        'application',
        'session_id',
        'ip',
        'user_agent',
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * @param  array<array-key, mixed>  $values
     * @return array<string, int|string|null>
     */
    public static function allowlist(array $values): array
    {
        $context = [];

        foreach (self::KEYS as $key) {
            $value = $values[$key] ?? null;

            $context[$key] = is_int($value) || is_string($value) ? $value : null;
        }

        return $context;
    }

    /**
     * @param  mixed  $key
     * @return ?string
     */
    public static function scalarKey(mixed $key): ?string
    {
        return is_int($key) || is_string($key) ? (string) $key : null;
    }
}
