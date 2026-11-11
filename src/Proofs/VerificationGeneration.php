<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Proofs;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Database\IdentityStateRow;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Database\StorageTransaction;
use SineMacula\Laravel\Mfa\Database\WriteConnection;

/**
 * A durable counter stamped on every proof; advancing it invalidates every
 * earlier proof. Read from the write connection so a lagging replica revives
 * none.
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
     * 0 for an identity with no row.
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
     * Joins the identity's factor state transaction when called inside it, and
     * throws when no row changed rather than let old proofs count.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $identity
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public static function advance(Authenticatable $identity): int
    {
        $owner      = ProofOwner::of($identity);
        $connection = self::connection();

        return StorageTransaction::run(static function () use ($connection, $owner): int {

            IdentityStateRow::lock($owner, $connection);

            $changed = IdentityStateRow::of($owner, $connection)->increment(self::COLUMN);

            if ($changed !== 1) {
                throw new \LogicException('The identity\'s verification generation was not advanced: its state row was not found once locked.');
            }

            $generation = IdentityStateRow::of($owner, $connection)->value(self::COLUMN);

            return is_numeric($generation) ? (int) $generation : 0;
        });
    }

    /**
     * @return \Illuminate\Database\ConnectionInterface
     *
     * @throws \InvalidArgumentException
     */
    private static function connection(): ConnectionInterface
    {
        return DB::connection(StorageConnection::name());
    }
}
