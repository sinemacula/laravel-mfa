<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\TableNames;
use SineMacula\Laravel\Mfa\Database\WriteConnection;

/**
 * An identity's verification generation: a durable counter on its row in the
 * identity states table, stamped on every proof the identity makes. Advancing
 * it invalidates every proof recorded under an earlier generation, on every
 * session at once, so the identity's other sessions must verify again; it is
 * how the package revokes sessions when no authentication layer is bound.
 *
 * An identity with no row is at generation 0. The generation is read from the
 * write connection, so a replica lagging behind an advance never lets an
 * invalidated proof count. Advancing runs on the storage connection; called
 * inside the identity's factor state transaction (see
 * `Support\FactorStateTransaction`), it joins it and commits or rolls back with
 * the change that advanced it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class VerificationGeneration
{
    /** @var string The column holding the generation. */
    private const string COLUMN = 'verification_generation';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The identity's current verification generation.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return int
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function current(Authenticatable $identity): int
    {
        $owner = ProofOwner::of($identity);

        $generation = WriteConnection::query(IdentityStateRow::of($owner))->value(self::COLUMN);

        return is_numeric($generation) ? (int) $generation : 0;
    }

    /**
     * Advance the identity's verification generation, creating its row when it
     * has none, and return the new generation. Every proof recorded under an
     * earlier generation stops counting.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return int
     *
     * @throws \Throwable
     */
    public static function advance(Authenticatable $identity): int
    {
        $owner      = ProofOwner::of($identity);
        $connection = self::connection();

        return StorageTransaction::run(static function () use ($connection, $owner): int {

            $now = CarbonImmutable::now();

            $connection->table(TableNames::of(TableNames::IDENTITY_STATES))->insertOrIgnore([
                'id'                   => Str::lower((string) Str::ulid()),
                'authenticatable_type' => $owner->type,
                'authenticatable_id'   => $owner->key,
                'created_at'           => $now,
                'updated_at'           => $now,
            ]);

            IdentityStateRow::of($owner, $connection)->increment(self::COLUMN, 1, ['updated_at' => $now]);

            $generation = IdentityStateRow::of($owner, $connection)->value(self::COLUMN);

            return is_numeric($generation) ? (int) $generation : 0;
        });
    }

    /**
     * The storage connection, where the identity states table lives.
     *
     * @return \Illuminate\Database\ConnectionInterface
     *
     * @throws \InvalidArgumentException
     */
    private static function connection(): ConnectionInterface
    {
        return DB::connection(StorageConnection::name());
    }
}
