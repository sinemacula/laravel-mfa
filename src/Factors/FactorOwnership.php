<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Factors;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Mfa\Contracts\EloquentFactor;
use SineMacula\Laravel\Mfa\Contracts\Factor;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException;
use SineMacula\Laravel\Mfa\Support\CurrentIdentity;
use SineMacula\Laravel\Mfa\Support\FactorOwnerColumns;

/**
 * Checks that a factor belongs to an identity, closing the cross-account
 * factor-tampering primitive on every operation that takes a factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FactorOwnership
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Verify that the given factor belongs to the supplied identity.
     *
     * Eloquent factors are matched by morph columns read directly off the model
     * attributes (no query triggered), against the identity's morph class so an
     * application's morph map is honoured. Non-Eloquent factors are matched by
     * the `getAuthenticatable()` accessor, which the contract guarantees does
     * not lazy-load, comparing class name and identifier. Either path throws
     * `FactorOwnershipMismatchException` on mismatch (or on a non-Eloquent
     * factor whose owner is unknown).
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\Factor  $factor
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\FactorOwnershipMismatchException
     */
    public static function assert(Factor $factor, MultiFactorAuthenticatable $identity): void
    {
        $expectedId = $identity->getAuthIdentifier();

        if ($factor instanceof EloquentFactor && $factor instanceof Model) {
            [$typeColumn, $keyColumn] = FactorOwnerColumns::of($factor);

            $factorType = $factor->getAttribute($typeColumn);
            $factorId   = $factor->getAttribute($keyColumn);
            $matches    = $factorType === CurrentIdentity::typeOf($identity) && self::isSameIdentifier($factorId, $expectedId);
        } else {
            $owner   = $factor->getAuthenticatable();
            $matches = $owner !== null
                && $owner::class === $identity::class
                && self::isSameIdentifier($owner->getAuthIdentifier(), $expectedId);
        }

        if (!$matches) {
            throw FactorOwnershipMismatchException::for($factor, $identity);
        }
    }

    /**
     * Compare two auth identifiers under the package's safe-cast rule: both
     * sides must be string|int, and their string representation must match.
     * Anything non-scalar collapses to `false` so the ownership check fails
     * closed rather than treating an unsupported identifier shape as equal.
     *
     * @param  mixed  $left
     * @param  mixed  $right
     * @return bool
     */
    private static function isSameIdentifier(mixed $left, mixed $right): bool
    {
        if ((!is_string($left) && !is_int($left)) || (!is_string($right) && !is_int($right))) {
            return false;
        }

        return (string) $left === (string) $right;
    }
}
