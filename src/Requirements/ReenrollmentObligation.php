<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Requirements;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\WriteConnection;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The flag a reset leaves, requiring an additional verification at sign-in
 * until a factor is confirmed; read from the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReenrollmentObligation
{
    /** @var string Column on the identity states table. */
    private const string COLUMN = 'reenrollment_required';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
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
     * Called under the identity's factor state lock, so it commits or rolls
     * back with the reset.
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
     * Called under the identity's factor state lock, so it commits or rolls
     * back with the confirmation.
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
