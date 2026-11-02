<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Mfa\Testing\Seams;

use Illuminate\Container\Container;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Mfa\Assurance\ObservedProperties;
use SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable;
use SineMacula\Laravel\Mfa\Enums\Purpose;
use SineMacula\Laravel\Mfa\Models\PasskeyAssociation;
use SineMacula\Laravel\Mfa\Passkeys\CredentialId;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyChangeGate;
use SineMacula\Laravel\Mfa\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Mfa\Proofs\ProofBinding;
use SineMacula\Laravel\Mfa\Proofs\ProofOwner;

/**
 * What a registration path's wiring to `Passkeys\PasskeyChangeGate` must
 * guarantee, as assertions: the gate is called inside the registration's own
 * change, so a registration the gate refuses keeps nothing; and the gate itself
 * refuses a call made outside a transaction.
 *
 * The closures given register a passkey through the path under test, and say
 * whether its credential was kept. The gate is made to refuse by associating
 * the credential with another identity first, which needs no arrangement of the
 * session.
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
     * Each of the gate's calls refuses with a `LogicException` outside a
     * transaction on the storage connection.
     *
     * @param  \SineMacula\Laravel\Mfa\Contracts\MultiFactorAuthenticatable  $identity
     * @param  string  $application
     * @return void
     *
     * @throws \SineMacula\Laravel\Mfa\Exceptions\UnsupportedIdentifierException
     */
    public static function assertTheGateNeedsTheCallersTransaction(MultiFactorAuthenticatable $identity, string $application): void
    {
        $gate         = Container::getInstance()->make(PasskeyChangeGate::class);
        $owner        = ProofOwner::of($identity);
        $registration = new PasskeyRegistration(
            self::CREDENTIAL,
            new ObservedProperties(userPresence: true),
            new ProofBinding($owner->type, $owner->key, $application, 'contract-sign-in', Purpose::ENROLLMENT),
        );

        $calls = [
            static fn () => $gate->registering($identity, $application, $registration),
            static fn () => $gate->removing($identity, $application, self::CREDENTIAL),
            static fn () => $gate->changing($identity, $application, self::CREDENTIAL),
        ];

        foreach ($calls as $call) {
            $outcome = null;

            try {
                $call();
            } catch (\Throwable $exception) {
                $outcome = $exception;
            }

            Assert::assertInstanceOf(\LogicException::class, $outcome, 'The gate must refuse a call made outside the caller\'s transaction.');
        }
    }
}
