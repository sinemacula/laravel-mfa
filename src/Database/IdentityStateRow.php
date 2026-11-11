<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Database;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

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
            ->where('authenticatable_type', $owner->type)
            ->where('authenticatable_id', $owner->key);
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
        $now = CarbonImmutable::now();

        $connection->table(TableNames::of(TableNames::IDENTITY_STATES))->upsert([[
            'id'                   => Str::lower((string) Str::ulid()),
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key,
            'created_at'           => $now,
            'updated_at'           => $now,
        ]], ['authenticatable_type', 'authenticatable_id'], ['updated_at']);
    }
}
