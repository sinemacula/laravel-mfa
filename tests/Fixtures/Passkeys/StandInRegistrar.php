<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Database\StorageConnection;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;

/**
 * Stands in for an authentication layer's passkey registration and removal: it
 * writes or deletes its own credential row in `test_credentials` and calls the
 * change gate, both inside one transaction on the storage connection, as the
 * gate requires. A callback given runs after the gate, inside the same
 * transaction, so a test can make the caller fail once the gate has allowed the
 * change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class StandInRegistrar
{
    /** @var string The stand-in credentials table. */
    public const string TABLE = 'test_credentials';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate  $gate
     */
    public function __construct(

        /** The gate the registrar calls. */
        private PasskeyChangeGate $gate,
    ) {}

    /**
     * Store the credential and associate it through the gate, in one
     * transaction.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration  $registration
     * @param  ?\Closure(): void  $after
     * @return ?\SineMacula\Laravel\Mfa\Passkeys\PasskeyAssociationResult
     *
     * @throws \Throwable
     */
    public function register(MultiFactorAuthenticatable $identity, string $application, PasskeyRegistration $registration, ?\Closure $after = null): ?PasskeyAssociationResult
    {
        return DB::connection(StorageConnection::name())->transaction(function () use ($identity, $application, $registration, $after): ?PasskeyAssociationResult {

            DB::connection(StorageConnection::name())->table(self::TABLE)->insert([
                'owner'         => self::owner($identity),
                'credential_id' => $registration->credentialId,
            ]);

            $result = $this->gate->registering($identity, $application, $registration);

            if ($after !== null) {
                $after();
            }

            return $result;
        });
    }

    /**
     * Delete the credential and remove its factor through the gate, in one
     * transaction.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @param  string  $credentialId
     * @param  ?\Closure(): void  $after
     * @return void
     *
     * @throws \Throwable
     */
    public function remove(MultiFactorAuthenticatable $identity, string $application, string $credentialId, ?\Closure $after = null): void
    {
        DB::connection(StorageConnection::name())->transaction(function () use ($identity, $application, $credentialId, $after): void {

            DB::connection(StorageConnection::name())->table(self::TABLE)->where('credential_id', $credentialId)->delete();

            $this->gate->removing($identity, $application, $credentialId);

            if ($after === null) {
                return;
            }

            $after();
        });
    }

    /**
     * Store the identity's credential without the gate, as a faulty caller
     * would.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return void
     */
    public static function store(MultiFactorAuthenticatable $identity, string $credentialId): void
    {
        DB::connection(StorageConnection::name())->table(self::TABLE)->insert([
            'owner'         => self::owner($identity),
            'credential_id' => $credentialId,
        ]);
    }

    /**
     * Whether the identity's credential is stored.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $credentialId
     * @return bool
     */
    public static function stores(MultiFactorAuthenticatable $identity, string $credentialId): bool
    {
        return DB::connection(StorageConnection::name())->table(self::TABLE)
            ->where('owner', self::owner($identity))
            ->where('credential_id', $credentialId)
            ->exists();
    }

    /**
     * The identity's key as the credential row stores it.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @return string
     */
    private static function owner(MultiFactorAuthenticatable $identity): string
    {
        $key = $identity->getAuthIdentifier();

        return is_int($key) || is_string($key) ? (string) $key : '';
    }
}
