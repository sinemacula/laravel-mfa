<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * An owner's row in the identity states table, matched on the owner columns, so
 * every reader of the identity's durable state names the row the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityStateRow
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A query for the owner's row, on the given connection or, without one, on
     * the storage connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  ?\Illuminate\Database\ConnectionInterface  $connection
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    public static function of(ProofOwner $owner, ?ConnectionInterface $connection = null): Builder
    {
        $connection ??= DB::connection(StorageConnection::name());

        return $connection->table(TableNames::of(TableNames::IDENTITY_STATES))
            ->where('authenticatable_type', $owner->type)
            ->where('authenticatable_id', $owner->key);
    }
}
