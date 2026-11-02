<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * An identity's re-enrolment obligation: the durable flag a reset leaves on its
 * row in the identity states table, which obliges it to enrol again before a
 * sign-in completes and ends when a factor is confirmed. While it is set, every
 * application requires an additional verification of the identity's sign-ins,
 * whatever its own setting.
 *
 * The flag is read from the write connection, so a replica lagging behind a
 * reset never lets a sign-in skip it. An identity with no row has no
 * obligation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReenrollmentObligation
{
    /** @var string The column holding the obligation. */
    private const string COLUMN = 'reenrollment_required';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the identity is obliged to enrol again.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function isRequired(Authenticatable $identity): bool
    {
        $required = WriteConnection::query(IdentityStateRow::of(ProofOwner::of($identity)))->value(self::COLUMN);

        return filter_var($required, FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * Record whether the identity is obliged to enrol again, as a reset states:
     * `false` clears an obligation an earlier reset left. Called inside the
     * identity's factor state transaction, whose lock holds the row, it commits
     * or rolls back with the reset.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @param  bool  $required
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function record(Authenticatable $identity, bool $required): void
    {
        IdentityStateRow::of(ProofOwner::of($identity))->update([self::COLUMN => $required]);
    }

    /**
     * End the identity's obligation, as confirming a factor does. Called inside
     * the identity's factor state transaction, it commits or rolls back with
     * the confirmation.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function end(Authenticatable $identity): void
    {
        self::record($identity, false);
    }
}
