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
 * guarantee: the gate runs inside the registration's own transaction, so a
 * refusal keeps nothing. The gate is made to refuse by associating the
 * credential with another identity first.
 *
 * The path must call the gate before taking its own session rows, so the
 * package's rows lock first; these assertions cannot see that order.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final class PasskeyChangeGateContract
{
    /** @var string Canonical unpadded base64url. */
    public const string CREDENTIAL = 'Y29udHJhY3QtY3JlZGVudGlhbA';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
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
     * Each call must throw a `LogicException` outside a storage transaction, so
     * the path neither opens its own nor swallows the refusal. Call this
     * outside any transaction on that connection.
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
     * `null` when the call threw nothing.
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
