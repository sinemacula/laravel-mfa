<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * What a registration path's wiring to `Passkeys\PasskeyChangeGate` must
 * guarantee, as assertions: the gate is called inside the registration's own
 * change, so a registration the gate refuses keeps nothing; and the path's own
 * calls into the gate refuse a call made outside a transaction, so a path that
 * opens one of its own around the gate, or swallows its refusal, is caught.
 *
 * The closures given register a passkey through the path under test, and say
 * whether its credential was kept. The gate is made to refuse by associating
 * the credential with another identity first, which needs no arrangement of the
 * session.
 *
 * The path must call the gate before it takes its own session rows, so that the
 * package's rows are locked first in every change. These assertions cannot see
 * that order; the path's own tests must.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class PasskeyChangeGateContract
{
    /** @var string The credential the contract registers, canonical unpadded base64url. */
    public const string CREDENTIAL = 'Y29udHJhY3QtY3JlZGVudGlhbA';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A registration the gate refuses fails, keeps no credential and associates
     * nothing with the identity.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, string): mixed  $register
     * @param  \Closure(\SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable, string): bool  $isStored
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function assertARefusedGateRollsBackTheRegistration(MultiFactorAuthenticatable $identity, \Closure $register, \Closure $isStored): void
    {
        $owner = ProofOwner::of($identity);

        (new PasskeyAssociation([
            'factor_id'            => 'contract-other-factor',
            'authenticatable_type' => $owner->type,
            'authenticatable_id'   => $owner->key . '-other',
            'credential_id_hash'   => CredentialId::hash(self::CREDENTIAL),
            'credential_id'        => self::CREDENTIAL,
        ]))->save();

        $outcome = null;

        try {
            $register($identity, self::CREDENTIAL);
        } catch (\Throwable $exception) {
            $outcome = $exception;
        }

        Assert::assertNotNull($outcome, 'A registration the gate refuses must fail.');
        Assert::assertFalse($isStored($identity, self::CREDENTIAL), 'A registration the gate refuses must keep no credential.');
        Assert::assertFalse(
            PasskeyAssociation::query()->where('authenticatable_type', $owner->type)->where('authenticatable_id', $owner->key)->exists(),
            'A registration the gate refuses must associate nothing.',
        );
    }

    /**
     * The path's calls into the gate, registering and removing a passkey with
     * the contract's credential id, each refuse with a `LogicException` outside
     * a transaction on the storage connection: the path neither opens one of
     * its own around the gate nor swallows its refusal. The check must itself
     * be made outside any transaction on that connection.
     *
     * @param  \Closure(string): mixed  $registering
     * @param  \Closure(string): mixed  $removing
     * @return void
     */
    public static function assertTheGateNeedsTheCallersTransaction(\Closure $registering, \Closure $removing): void
    {
        Assert::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel(), 'The check must be made outside any transaction on the storage connection.');

        $registration = self::outcomeOf(static fn () => $registering(self::CREDENTIAL));
        $removal      = self::outcomeOf(static fn () => $removing(self::CREDENTIAL));

        Assert::assertInstanceOf(\LogicException::class, $registration, 'The path must refuse to register a passkey outside the caller\'s transaction.');
        Assert::assertInstanceOf(\LogicException::class, $removal, 'The path must refuse to remove a passkey outside the caller\'s transaction.');
    }

    /**
     * What a call threw, or `null` when it threw nothing.
     *
     * @param  \Closure(): mixed  $call
     * @return ?\Throwable
     */
    private static function outcomeOf(\Closure $call): ?\Throwable
    {
        try {
            $call();
        } catch (\Throwable $exception) {
            return $exception;
        }

        return null;
    }
}
