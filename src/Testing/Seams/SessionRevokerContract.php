<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * What every `SessionRevoker` must guarantee, as assertions: revoking the other
 * sessions, or all of them, stops another session counting, and a revocation
 * inside a change that rolls back leaves it counting.
 *
 * What "counting" means is the implementation's: the closures given verify
 * another session of the identity and say whether it still counts. A revoker
 * that ends sessions passes; so does one that only stops their proofs counting,
 * as the package's default does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class SessionRevokerContract
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Revoking the identity's other sessions stops another session counting.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @return void
     */
    public static function assertRevokingOthersStopsAnotherSessionCounting(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        \Closure $verifyOther,
        \Closure $otherCounts,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $revoker->revokeOthers($identity);

        Assert::assertFalse($otherCounts($identity), 'Revoking the other sessions must stop another session counting.');
    }

    /**
     * Revoking every session stops another session counting.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @return void
     */
    public static function assertRevokingAllStopsAnotherSessionCounting(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        \Closure $verifyOther,
        \Closure $otherCounts,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $revoker->revokeAll($identity);

        Assert::assertFalse($otherCounts($identity), 'Revoking every session must stop another session counting.');
    }

    /**
     * A revocation inside a change on the storage connection that rolls back
     * leaves another session counting.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertARolledBackRevocationLeavesSessionsCounting(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        \Closure $verifyOther,
        \Closure $otherCounts,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        try {
            $revoker->revokeOthers($identity);
        } finally {
            $connection->rollBack();
        }

        Assert::assertTrue($otherCounts($identity), 'A revocation that rolls back must leave the other sessions counting.');
    }

    /**
     * Verify another session of the identity, and check that it counts.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @return void
     */
    private static function verify(MultiFactorAuthenticatable $identity, \Closure $verifyOther, \Closure $otherCounts): void
    {
        $verifyOther($identity);

        Assert::assertTrue($otherCounts($identity), 'Another session verified for the contract must count before it is revoked.');
    }
}
