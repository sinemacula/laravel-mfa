<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Events;

/**
 * The shape of every event's context: who and what the event is about, as an
 * allowlist of scalar values. Every key is present, `null` when it is not
 * known: the identity's type and id, the principal's type and id, the active
 * tenant's id, the application, the session's id, and the request's IP address
 * and user agent.
 *
 * A context resolver an application binds may return anything; what reaches an
 * event is cut down to these keys and to integers and strings, so a model, an
 * array or an object it returns by mistake never travels in a payload.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class EventContext
{
    /** @var list<string> The keys of every event's context, in order. */
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
     * Cut the values down to the context's keys, each an integer, a string or
     * `null`; a key that is missing, or holds anything else, is `null`.
     *
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
     * An identifier as a string: an integer or a string as one, anything else
     * `null`.
     *
     * @param  mixed  $key
     * @return ?string
     */
    public static function scalarKey(mixed $key): ?string
    {
        return is_int($key) || is_string($key) ? (string) $key : null;
    }
}
