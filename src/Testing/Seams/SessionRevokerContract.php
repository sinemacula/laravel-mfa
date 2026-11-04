<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * What every `SessionRevoker` must guarantee, as assertions: a factor's
 * removal, or revoking every session, stops another session counting; a
 * factor's removal never spares a session other than the sign-in it was made
 * from; and a revocation inside a change that rolls back leaves another session
 * counting.
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
     * A factor's removal from the identity's current sign-in stops another
     * session counting, and answers what it did.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $session
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @return void
     */
    public static function assertRemovingAFactorStopsAnotherSessionCounting(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        string $factorId,
        string $session,
        \Closure $verifyOther,
        \Closure $otherCounts,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $revoker->factorRemoved($identity, $factorId, $session);

        Assert::assertFalse($otherCounts($identity), 'Removing a factor must stop another session counting.');
    }

    /**
     * A factor's removal named as made from a sign-in that is not the
     * identity's current one never spares the current session: the revoker
     * throws, or the current session stops counting with the others.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $otherSession
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $currentCounts
     * @return void
     */
    public static function assertRemovingAFactorFromAnotherSignInSparesNothing(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        string $factorId,
        string $otherSession,
        \Closure $currentCounts,
    ): void {
        Assert::assertTrue($currentCounts($identity), 'The identity\'s current session must count before a factor is removed.');

        try {
            $revoker->factorRemoved($identity, $factorId, $otherSession);
        } catch (\Throwable) {
            return;
        }

        Assert::assertFalse($currentCounts($identity), 'A factor\'s removal from another sign-in must not spare the current session.');
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
     * @param  string  $factorId
     * @param  string  $session
     * @return void
     *
     * @throws \Throwable
     */
    public static function assertARolledBackRevocationLeavesSessionsCounting(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        \Closure $verifyOther,
        \Closure $otherCounts,
        string $factorId,
        string $session,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        try {
            $revoker->factorRemoved($identity, $factorId, $session);
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
