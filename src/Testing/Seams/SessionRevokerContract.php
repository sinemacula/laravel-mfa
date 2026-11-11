<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Contracts\SessionRevoker;
use SineMacula\Laravel\Mfa\Database\StorageConnection;

/**
 * What every `SessionRevoker` must guarantee: a factor's removal or revoking
 * all stops another session counting, a removal spares only the sign-in it was
 * made from, and a rolled-back revocation changes nothing. The closures define
 * "counting", so ending sessions and voiding their proofs both pass.
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
     * The revoker must also answer what it did.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $session
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @return void
     */
    public static function assertRemovingAFactorStopsAnotherSessionCounting(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        string $factorId,
        string $application,
        string $session,
        \Closure $verifyOther,
        \Closure $otherCounts,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $revoker->factorRemoved($identity, $factorId, $application, $session);

        Assert::assertFalse($otherCounts($identity), 'Removing a factor must stop another session counting.');
    }

    /**
     * The revoker throws, or the current session stops counting with the
     * others.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $factorId
     * @param  string  $application
     * @param  string  $otherSession
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $currentCounts
     * @return void
     */
    public static function assertRemovingAFactorFromAnotherSignInSparesNothing(
        SessionRevoker $revoker,
        MultiFactorAuthenticatable $identity,
        string $factorId,
        string $application,
        string $otherSession,
        \Closure $currentCounts,
    ): void {
        Assert::assertTrue($currentCounts($identity), 'The identity\'s current session must count before a factor is removed.');

        try {
            $revoker->factorRemoved($identity, $factorId, $application, $otherSession);
        } catch (\Throwable) {
            return;
        }

        Assert::assertFalse($currentCounts($identity), 'A factor\'s removal from another sign-in must not spare the current session.');
    }

    /**
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
     * @param  \SineMacula\Laravel\Mfa\Contracts\SessionRevoker  $revoker
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): void  $verifyOther
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable): bool  $otherCounts
     * @param  string  $factorId
     * @param  string  $application
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
        string $application,
        string $session,
    ): void {
        self::verify($identity, $verifyOther, $otherCounts);

        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();

        try {
            $revoker->factorRemoved($identity, $factorId, $application, $session);
        } finally {
            $connection->rollBack();
        }

        Assert::assertTrue($otherCounts($identity), 'A revocation that rolls back must leave the other sessions counting.');
    }

    /**
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
