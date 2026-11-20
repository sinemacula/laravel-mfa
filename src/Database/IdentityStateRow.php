<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Models\IdentityState;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * The one way to query and lock an owner's identity state row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentityStateRow
{
    /**
     * Defaults to the storage connection.
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
            ->where('owner_hash', $owner->hash());
    }

    /**
     * Lock the owner's row until the transaction ends, creating it if missing.
     * The upsert locks in one statement even when two first changes race.
     *
     * @param  \SineMacula\Laravel\Mfa\Proofs\ProofOwner  $owner
     * @param  \Illuminate\Database\ConnectionInterface  $connection
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function lock(ProofOwner $owner, ConnectionInterface $connection): void
    {
        $now = (new IdentityState)->freshTimestampString();

        $connection->table(TableNames::of(TableNames::IDENTITY_STATES))->upsert([[
            'id'                   => Str::lower((string) Str::ulid()),
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'owner_hash'           => $owner->hash(),
            'created_at'           => $now,
            'updated_at'           => $now,
        ]], ['owner_hash'], ['updated_at']);
    }
}
